//! Cross-function call graph + cached summaries (spec §15, §16).
//!
//! The call graph is a directed multi-graph from `FuncId` to `FuncId`. Each
//! edge carries its precision so downstream queries can decide how much to
//! trust it. Summaries are compositional cached facts derived from a
//! function's CFG plus the summaries of every target it calls.

pub mod chains;

pub use chains::{
    downstream_funcs_set, enumerate_chains_resolved, is_precise_chain, ChainTruncation, ResolvedChain,
};

use ahash::{AHashMap, AHashSet};
use bonsai_common::{
    callable_reference_variants, short_qualified_tail, FileId, FuncId, Precision, Span, SymbolId,
};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{
    AliasTarget, AssignValueKind, CallArg, CallKind, Decl, DeclKind, FlowEvent, ModulePath,
};
use bonsai_resolve::{
    callee_without_call_args, collect_method_candidates_for_class, enclosing_class_for_decl,
    export_name_variants, extend_alias_targets_with_declared_types, is_super_receiver,
    module_target_matches_decl_module_path, module_target_matches_path, namespace_alias_target_tail,
    prune_receiver_type_names_for_dispatch, push_unique_func, push_unique_string,
    qualified_module_alias_call, resolve_callable_with_context, resolve_class, split_qualified_head_tail,
    visibility_allows, ResolveContext,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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
/// `FuncId → FuncId` link with the kind / precision tag the
/// resolver assigned at build time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallEdge {
    pub from: FuncId,
    pub to: FuncId,
    pub span: Span,
    pub kind: EdgeKind,
    pub precision: Precision,
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CallGraph {
    pub edges: Vec<CallEdge>,
    /// `caller → indices into `edges`` where the caller is `from`.
    outgoing: AHashMap<FuncId, Vec<usize>>,
    /// `callee → indices into `edges`` where the callee is `to`.
    incoming: AHashMap<FuncId, Vec<usize>>,
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
                let existing = &self.edges[idx];
                existing.to == edge.to
                    && existing.span.file == edge.span.file
                    && existing.span.start == edge.span.start
                    && existing.kind == edge.kind
                    && existing.precision == edge.precision
            })
        }) {
            return;
        }
        let idx = self.edges.len();
        self.outgoing.entry(edge.from).or_default().push(idx);
        self.incoming.entry(edge.to).or_default().push(idx);
        self.edges.push(edge);
    }

    /// Edges where `func` is the caller.
    pub fn callees(&self, func: FuncId) -> impl Iterator<Item = &CallEdge> {
        self.outgoing
            .get(&func)
            .into_iter()
            .flat_map(move |ids| ids.iter().map(move |i| &self.edges[*i]))
    }

    /// Edges where `func` is the callee.
    pub fn callers(&self, func: FuncId) -> impl Iterator<Item = &CallEdge> {
        self.incoming
            .get(&func)
            .into_iter()
            .flat_map(move |ids| ids.iter().map(move |i| &self.edges[*i]))
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
                    stack.push(self.edges[idx].to);
                }
            }
        }
        order
    }
}

/// Build-target membership inferred from checked-in Makefiles.
///
/// This is deliberately narrow: it only records object-list groups
/// that map back to workspace source files. C resolution uses it to
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
        let mut source_by_path: AHashMap<PathBuf, FileId> = AHashMap::new();
        let mut source_dirs: AHashSet<PathBuf> = AHashSet::new();
        for (file, path) in paths {
            let path = normalize_fs_path(PathBuf::from(path));
            if !is_c_family_source(&path) {
                continue;
            }
            if let Some(parent) = path.parent() {
                source_dirs.insert(parent.to_path_buf());
            }
            source_by_path.insert(path, file);
        }
        if source_by_path.is_empty() {
            return Self::default();
        }

        let Some(root) = common_source_root(source_by_path.keys()) else {
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
                    if let Some(file) = object_token_to_source_file(make_dir, &token, &source_by_path) {
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

fn normalize_fs_path(path: PathBuf) -> PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path)
}

fn is_c_family_source(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "c" | "h" | "cc" | "cpp" | "cxx" | "m" | "mm"))
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
    source_by_path: &AHashMap<PathBuf, FileId>,
) -> Option<FileId> {
    let token = token.trim_matches(|ch| matches!(ch, '"' | '\'' | ','));
    if !object_token_is_resolved(token) {
        return None;
    }
    let object_path = normalize_fs_path(make_dir.join(token));
    for ext in ["c", "cc", "cpp", "cxx", "m", "mm"] {
        let source_path = normalize_fs_path(object_path.with_extension(ext));
        if let Some(file) = source_by_path.get(&source_path) {
            return Some(*file);
        }
    }
    None
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
        Self { cg }
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
        mut aliases_for_file: F,
        mut alias_targets_for_file: T,
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
        let mut cg = CallGraph::new();
        let alias_index = WorkspaceAliasIndex::build(global);
        let files = global.all_files().collect::<Vec<_>>();
        let file_paths: AHashMap<FileId, String> = files
            .iter()
            .filter_map(|&file| path_for_file(file).map(|path| (file, path)))
            .collect();
        let build_targets =
            BuildTargetIndex::from_file_paths(file_paths.iter().map(|(&file, path)| (file, path.clone())));
        let path_lookup = |file| file_paths.get(&file).cloned();
        for file in files {
            let aliases = aliases_for_file(file);
            let file_alias_targets = alias_targets_for_file(file);
            let export_aliases = export_aliases_for_file(file);
            let caller_language = language_for_file(file);
            for decl in global.decls_in(file) {
                if !matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    continue;
                }
                let from = FuncId::new(decl.symbol.raw());
                let alias_targets = alias_targets_for_decl(&file_alias_targets, decl);
                let local_bindings = collect_local_callable_bindings_with_alias_index(
                    &decl.flow_events,
                    global,
                    decl,
                    &alias_targets,
                    &alias_index,
                );
                add_resolved_call_edges(
                    &decl.flow_events,
                    from,
                    decl,
                    global,
                    &aliases,
                    &alias_targets,
                    &local_bindings,
                    &path_lookup,
                    export_aliases,
                    caller_language,
                    &language_for_file,
                    &alias_index,
                    &build_targets,
                    &mut cg,
                );
            }
        }
        Self { cg }
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
}

/// Walk one decl's `flow_events` and emit a [`CallEdge`] per resolved
/// call site. Recurses through every structural variant (`Branch`,
/// `Loop`, `Try`, `Defer`, `Using`).
#[allow(clippy::too_many_arguments)] // stable parameter list — recursion calls hold it stable
fn add_resolved_call_edges(
    events: &[FlowEvent],
    from: FuncId,
    caller_decl: &Decl,
    global: &GlobalIndex,
    aliases: &AHashMap<String, String>,
    alias_targets: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    caller_export_aliases: &[&'static str],
    caller_language: Option<&'static str>,
    language_for_file: &dyn Fn(FileId) -> Option<&'static str>,
    alias_index: &WorkspaceAliasIndex,
    build_targets: &BuildTargetIndex,
    cg: &mut CallGraph,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                call_kind,
                span,
                args,
                ..
            } => {
                let short = short_callee(name);
                let alias_qualified_call = qualified_module_alias_call(name, aliases)
                    || qualified_alias_target_entry_tail(name, alias_targets).is_some();
                let folded_receiver = receiver_name_from_call_name(name).filter(|candidate| {
                    folded_call_name_receiver_is_instance(name, candidate, receiver_types)
                });
                let semantic_receiver = receiver.as_deref().or(folded_receiver);
                let mut candidates = if semantic_receiver.is_none() {
                    local_bindings
                        .get(name.as_str())
                        .or_else(|| {
                            (!alias_qualified_call)
                                .then(|| local_bindings.get(short))
                                .flatten()
                        })
                        .copied()
                        .into_iter()
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                if candidates.is_empty() && semantic_receiver.is_none() && !alias_qualified_call {
                    candidates = collect_nested_local_callable_targets(global, caller_decl, name, *span);
                }
                if candidates.is_empty() {
                    candidates = collect_receiver_method_targets(
                        global,
                        caller_decl,
                        alias_targets,
                        semantic_receiver,
                        receiver_types,
                        *call_kind,
                        name,
                        *span,
                    );
                }
                if candidates.is_empty() {
                    candidates =
                        collect_type_qualified_method_targets(global, caller_decl, alias_targets, name);
                }
                if candidates.is_empty() {
                    candidates =
                        collect_constructor_targets_for_class_call(global, caller_decl, alias_targets, name);
                }
                let typed_receiver_method = semantic_receiver.is_some() && !receiver_types.is_empty();
                if candidates.is_empty() && !typed_receiver_method {
                    candidates = collect_qualified_workspace_targets(
                        global,
                        name,
                        Some(aliases),
                        alias_targets,
                        path_for_file,
                        caller_export_aliases,
                        caller_decl,
                    );
                }
                let unresolved_method_receiver = candidates.is_empty()
                    && *call_kind == CallKind::Method
                    && semantic_receiver.is_some()
                    && !alias_qualified_call;
                let local_value_shadow = semantic_receiver.is_none()
                    && local_value_binding_shadows_callable(&caller_decl.flow_events, short, *span);
                if candidates.is_empty() && !unresolved_method_receiver && !local_value_shadow {
                    candidates = collect_callable_targets_with_context_aliases_and_paths(
                        global,
                        name,
                        caller_decl,
                        alias_targets,
                        path_for_file,
                    );
                }
                if candidates.is_empty()
                    && c_family_linked_language(caller_language)
                    && semantic_receiver.is_none()
                    && !local_value_shadow
                {
                    candidates = collect_c_linked_callable_targets(
                        global,
                        name,
                        caller_decl,
                        alias_targets,
                        build_targets,
                    );
                }
                if candidates.is_empty() && !unresolved_method_receiver {
                    if let Some((alias_target, alias_tail)) = qualified_alias_target_tail(name, aliases) {
                        candidates = collect_workspace_module_targets(
                            global,
                            alias_target,
                            alias_tail,
                            path_for_file,
                            caller_export_aliases,
                            caller_decl,
                            alias_targets,
                        );
                    }
                }
                if candidates.is_empty() && !unresolved_method_receiver {
                    if alias_qualified_call {
                        continue;
                    }
                    // Bare-name fallback for qualified syntaxes that
                    // do not carry import/alias evidence. If the head
                    // is a known alias, failing to resolve through
                    // that target means the call is external or
                    // unresolved; retrying the bare tail would invent
                    // a different call edge.
                    //
                    // For Rust-style `Type::method` qualified calls,
                    // allow the bare-tail fallback ONLY when the
                    // qualifier (`Type`) resolves through the
                    // workspace's alias_targets to an in-workspace
                    // class / module. External types
                    // (`Command::new` → `std::process::Command`)
                    // would otherwise collapse onto a user-defined
                    // `Repository::new` that shares the bare suffix,
                    // fabricating cross-call edges.
                    let qualified_owner_in_workspace = if let Some(idx) = name.find("::") {
                        let qualifier = &name[..idx];
                        let qualifier_resolves = alias_targets
                            .get(qualifier)
                            .map(|t| match t {
                                AliasTarget::Namespace { module } => {
                                    is_workspace_alias_target(alias_index, module)
                                }
                                AliasTarget::Member { module, member } => {
                                    // For Member-form aliases the local
                                    // name typically rebinds to
                                    // `module::member` (e.g.
                                    // `use crate::storage as store` →
                                    // store → Member { module="crate",
                                    // member="storage" }). Honour both
                                    // segments so `store::persist`
                                    // resolves through the workspace.
                                    is_workspace_alias_target(alias_index, module)
                                        || is_workspace_alias_target(alias_index, member)
                                }
                                AliasTarget::Type { .. } => true,
                            })
                            .unwrap_or(false);
                        qualifier_resolves
                    } else {
                        // No `::` — receiver / dotted form. Existing
                        // behaviour applies.
                        true
                    };
                    if qualified_owner_in_workspace {
                        let resolved_name = aliases.get(short).map(String::as_str).unwrap_or(short);
                        if resolved_name != name.as_str() {
                            candidates = collect_callable_targets_with_context_aliases_and_paths(
                                global,
                                resolved_name,
                                caller_decl,
                                alias_targets,
                                path_for_file,
                            );
                        }
                    }
                    if candidates.is_empty()
                        && (colon_remote_call(name) || qualified_module_alias_call(name, aliases))
                    {
                        continue;
                    }
                }
                if !candidates.is_empty() {
                    retain_same_language_candidates(
                        global,
                        caller_language,
                        language_for_file,
                        &mut candidates,
                    );
                }
                if c_family_linked_language(caller_language) && !candidates.is_empty() {
                    build_targets.retain_candidates_linked_with(
                        global,
                        caller_decl.name_span.file,
                        &mut candidates,
                    );
                }
                if !candidates.is_empty() {
                    retain_assigned_receiver_method_candidates(
                        global,
                        caller_decl,
                        alias_targets,
                        semantic_receiver,
                        *span,
                        &mut candidates,
                    );
                }
                if !candidates.is_empty() {
                    retain_semantic_receiver_evidenced_candidates(
                        global,
                        caller_decl,
                        alias_targets,
                        semantic_receiver,
                        receiver_types,
                        *call_kind,
                        *span,
                        alias_qualified_call,
                        path_for_file,
                        &mut candidates,
                    );
                }
                if !candidates.is_empty() {
                    let receiver_supplied = semantic_receiver.is_some() || *call_kind == CallKind::Method;
                    retain_signature_compatible_candidates(
                        global,
                        caller_decl,
                        &mut candidates,
                        args,
                        receiver_supplied,
                    );
                }
                dedup_func_ids(&mut candidates);
                dedup_semantic_candidate_decls(global, &mut candidates);
                if !candidates.is_empty() {
                    // No fan-out cap. Caps are heuristics, and per
                    // docs/contributing/design-patterns.mdx::Semantic Resolution
                    // Always the engine resolves callees by semantic
                    // identity (Visibility, module_path, receiver
                    // type, alias map). When that pipeline still
                    // produces many candidates, the workspace
                    // genuinely has that many — a cap would silently
                    // drop edges that downstream passes need. If
                    // fan-out is still too wide for a particular
                    // language, the right fix is enriching adapter
                    // facts (typed receivers, accurate module
                    // boundaries) until the resolver narrows
                    // semantically.
                    let semantic_virtual = candidates.len() > 1
                        && *call_kind == CallKind::Method
                        && semantic_receiver.is_some()
                        && !receiver_types.is_empty();
                    let same_decl_family =
                        candidate_set_is_same_decl_family(global, &candidates, caller_language);
                    let Some((kind, precision)) =
                        semantic_edge_shape(candidates.len(), semantic_virtual || same_decl_family)
                    else {
                        continue;
                    };
                    for to in candidates {
                        cg.add_edge(CallEdge {
                            from,
                            to,
                            span: *span,
                            kind,
                            precision,
                        });
                    }
                }
                add_callback_arg_edges(
                    args,
                    from,
                    caller_decl,
                    global,
                    alias_targets,
                    local_bindings,
                    caller_language,
                    language_for_file,
                    cg,
                );
            }
            FlowEvent::Assign {
                source_call: Some(name),
                source_call_args,
                span,
                ..
            } => {
                if assign_source_call_shadowed_by_explicit_call(events, name, *span) {
                    continue;
                }
                let mut candidates = collect_assign_source_call_targets(
                    global,
                    name,
                    caller_decl,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    *span,
                );
                if !candidates.is_empty() {
                    retain_same_language_candidates(
                        global,
                        caller_language,
                        language_for_file,
                        &mut candidates,
                    );
                }
                if caller_language == Some("c") && !candidates.is_empty() {
                    build_targets.retain_candidates_linked_with(
                        global,
                        caller_decl.name_span.file,
                        &mut candidates,
                    );
                }
                if !candidates.is_empty() {
                    retain_assigned_receiver_constructor_candidates(
                        global,
                        caller_decl,
                        alias_targets,
                        span,
                        &mut candidates,
                    );
                }
                if !candidates.is_empty() && assign_source_call_member_like(name) {
                    let receiver = receiver_name_from_call_name(name);
                    let alias_qualified_call =
                        qualified_alias_target_entry_tail(name, alias_targets).is_some();
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
                        &mut candidates,
                    );
                }
                if !candidates.is_empty() {
                    let receiver_supplied = assign_source_call_member_like(name);
                    retain_raw_signature_compatible_candidates(
                        global,
                        caller_decl,
                        &mut candidates,
                        source_call_args,
                        receiver_supplied,
                    );
                }
                dedup_func_ids(&mut candidates);
                dedup_semantic_candidate_decls(global, &mut candidates);
                if !candidates.is_empty() {
                    let same_decl_family =
                        candidate_set_is_same_decl_family(global, &candidates, caller_language);
                    let Some((kind, precision)) = semantic_edge_shape(candidates.len(), same_decl_family)
                    else {
                        continue;
                    };
                    for to in candidates {
                        cg.add_edge(CallEdge {
                            from,
                            to,
                            span: *span,
                            kind,
                            precision,
                        });
                    }
                }
                let args = source_call_args
                    .iter()
                    .map(|value_text| CallArg {
                        span: *span,
                        name: None,
                        value_text: value_text.clone(),
                        place: None,
                        source_names: Vec::new(),
                    })
                    .collect::<Vec<_>>();
                add_callback_arg_edges(
                    &args,
                    from,
                    caller_decl,
                    global,
                    alias_targets,
                    local_bindings,
                    caller_language,
                    language_for_file,
                    cg,
                );
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                add_resolved_call_edges(
                    then_events,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    caller_language,
                    language_for_file,
                    alias_index,
                    build_targets,
                    cg,
                );
                add_resolved_call_edges(
                    else_events,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    caller_language,
                    language_for_file,
                    alias_index,
                    build_targets,
                    cg,
                );
            }
            FlowEvent::Loop { body, .. } => {
                add_resolved_call_edges(
                    body,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    caller_language,
                    language_for_file,
                    alias_index,
                    build_targets,
                    cg,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                add_resolved_call_edges(
                    body,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    caller_language,
                    language_for_file,
                    alias_index,
                    build_targets,
                    cg,
                );
                add_resolved_call_edges(
                    catch_events,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    caller_language,
                    language_for_file,
                    alias_index,
                    build_targets,
                    cg,
                );
                add_resolved_call_edges(
                    finally_events,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    caller_language,
                    language_for_file,
                    alias_index,
                    build_targets,
                    cg,
                );
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                add_resolved_call_edges(
                    body,
                    from,
                    caller_decl,
                    global,
                    aliases,
                    alias_targets,
                    local_bindings,
                    path_for_file,
                    caller_export_aliases,
                    caller_language,
                    language_for_file,
                    alias_index,
                    build_targets,
                    cg,
                );
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
fn add_callback_arg_edges(
    args: &[CallArg],
    from: FuncId,
    caller_decl: &Decl,
    global: &GlobalIndex,
    alias_targets: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    caller_language: Option<&'static str>,
    language_for_file: &dyn Fn(FileId) -> Option<&'static str>,
    cg: &mut CallGraph,
) {
    let mut seen = AHashSet::new();
    for arg in args {
        let targets = resolve_callable_arg(
            global,
            alias_targets,
            local_bindings,
            &arg.value_text,
            caller_decl,
        );
        let [to] = targets.as_slice() else {
            continue;
        };
        let to = *to;
        if !func_language_matches(global, caller_language, language_for_file, to) {
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
            call_names_match(source_call, name) && spans_overlap(assign_span, *span)
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

fn call_names_match(left: &str, right: &str) -> bool {
    left == right || short_callee(left) == short_callee(right)
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
    caller_export_aliases: &[&'static str],
    call_span: Span,
) -> Vec<FuncId> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let member_like = assign_source_call_member_like(trimmed);
    let short = short_callee(trimmed);
    let mut targets = if member_like {
        Vec::new()
    } else {
        local_bindings
            .get(trimmed)
            .or_else(|| local_bindings.get(short))
            .copied()
            .into_iter()
            .collect::<Vec<_>>()
    };
    if targets.is_empty() && !member_like {
        targets = collect_nested_local_callable_targets(global, caller_decl, trimmed, call_span);
    }
    if targets.is_empty() {
        targets = collect_callable_targets_with_context_aliases_and_paths(
            global,
            trimmed,
            caller_decl,
            alias_targets,
            path_for_file,
        );
    }
    if targets.is_empty() {
        if let Some((alias_target, alias_tail)) = namespace_alias_target_tail(trimmed, alias_targets) {
            targets = collect_workspace_module_targets(
                global,
                alias_target,
                alias_tail,
                path_for_file,
                caller_export_aliases,
                caller_decl,
                alias_targets,
            );
        }
    }
    if targets.is_empty() && !member_like && short != trimmed {
        targets = collect_callable_targets_with_context_aliases_and_paths(
            global,
            short,
            caller_decl,
            alias_targets,
            path_for_file,
        );
    }
    if targets.is_empty() {
        targets = collect_constructor_targets_for_class_call(global, caller_decl, alias_targets, trimmed);
    }
    targets
}

fn assign_source_call_member_like(name: &str) -> bool {
    name.contains('.')
        || name.contains("::")
        || name.contains('\\')
        || (name.contains(':') && !name.contains("::"))
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
            span.end <= call_span.start && normalize_receiver_alias_text(target) == target_name
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
) {
    if candidates.len() <= 1 {
        return;
    }
    retain_raw_signature_compatible_candidates(
        global,
        caller_decl,
        candidates,
        &args.iter().map(call_arg_lookup_text).collect::<Vec<_>>(),
        receiver_supplied,
    );
}

fn dedup_func_ids(candidates: &mut Vec<FuncId>) {
    let mut seen = AHashSet::new();
    candidates.retain(|func| seen.insert(*func));
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
    caller_language: Option<&'static str>,
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

    if matches!(caller_language, Some("elixir" | "erlang")) {
        return candidate_set_is_function_clause_family(global, candidates);
    }

    if caller_language != Some("c") {
        return false;
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

fn call_arg_lookup_text(arg: &CallArg) -> String {
    arg.place
        .as_deref()
        .filter(|place| !place.trim().is_empty())
        .unwrap_or(arg.value_text.as_str())
        .trim()
        .to_string()
}

fn retain_raw_signature_compatible_candidates(
    global: &GlobalIndex,
    caller_decl: &Decl,
    candidates: &mut Vec<FuncId>,
    arg_texts: &[String],
    receiver_supplied: bool,
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
            if let Some(match_score) = type_sets_match_score(&actual_types, &expected_types) {
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
    if let Some(type_name) = constructor_type_from_expression(binding) {
        push_unique_type_name(&mut out, &type_name);
        collect_declared_supertypes(global, decl, &type_name, &mut out);
    }
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

fn constructor_type_from_expression(expr: &str) -> Option<String> {
    let trimmed = expr.trim();
    let rest = trimmed.strip_prefix("new ")?;
    let open = rest.find('(')?;
    let type_name = rest[..open].trim();
    if type_name.is_empty() {
        return None;
    }
    Some(short_callee(type_name).to_string())
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

fn type_sets_match_score(actual: &[String], expected: &[String]) -> Option<usize> {
    let best = actual
        .iter()
        .filter_map(|left| {
            expected
                .iter()
                .filter_map(|right| type_name_match_score(left, right))
                .max()
        })
        .max();
    best
}

fn type_name_match_score(left: &str, right: &str) -> Option<usize> {
    let left = normalize_type_name(left);
    let right = normalize_type_name(right);
    if is_universal_type_name(&left) {
        return None;
    }
    if is_universal_type_name(&right) {
        return Some(1);
    }
    if left == right {
        return Some(2);
    }
    (short_callee(&left) == short_callee(&right)).then_some(2)
}

fn type_name_matches(left: &str, right: &str) -> bool {
    type_name_match_score(left, right).is_some()
}

fn is_universal_type_name(name: &str) -> bool {
    matches!(short_callee(name), "Object" | "Any" | "AnyObject" | "interface{}")
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
fn resolve_callable_arg(
    global: &GlobalIndex,
    alias_targets: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    raw: &str,
    caller_decl: &Decl,
) -> Vec<FuncId> {
    if !call_arg_can_be_callable_reference(raw) {
        return Vec::new();
    }
    let variants = callable_reference_variants(raw);
    let Some(first) = variants.first() else {
        return Vec::new();
    };
    // Lambda / template literals aren't callable references that
    // resolve to a workspace function — bail before we try.
    if first.contains("=>") || first.starts_with('`') {
        return Vec::new();
    }
    let original_alias_qualified = variants.iter().any(|variant| {
        let trimmed = variant.trim().trim_start_matches(bonsai_common::REFERENCE_SIGILS);
        alias_target_qualified_name(trimmed, alias_targets)
    });
    for variant in &variants {
        let trimmed = variant.trim().trim_start_matches(bonsai_common::REFERENCE_SIGILS);
        if trimmed.is_empty() {
            continue;
        }
        let short = short_callee(trimmed);
        let alias_qualified_reference = alias_target_qualified_name(trimmed, alias_targets);
        if original_alias_qualified && !alias_qualified_reference {
            continue;
        }
        if let Some(local) = local_bindings
            .get(trimmed)
            .or_else(|| {
                (!alias_qualified_reference)
                    .then(|| local_bindings.get(short))
                    .flatten()
            })
            .copied()
        {
            return vec![local];
        }
        let mut targets =
            collect_callable_targets_with_context_and_aliases(global, trimmed, caller_decl, alias_targets);
        if targets.is_empty() && short != trimmed && !alias_qualified_reference {
            targets =
                collect_callable_targets_with_context_and_aliases(global, short, caller_decl, alias_targets);
        }
        if !targets.is_empty() {
            return targets;
        }
    }
    Vec::new()
}

fn call_arg_can_be_callable_reference(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() || is_exact_quoted_literal(trimmed) {
        return false;
    }
    if trimmed.contains("=>") || trimmed.starts_with('`') {
        return false;
    }
    if trimmed.starts_with("method(") {
        return true;
    }
    !(trimmed.contains('(') || trimmed.contains(')'))
}

fn is_exact_quoted_literal(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && matches!(bytes[0], b'\'' | b'"' | b'`') && bytes.last().copied() == Some(bytes[0])
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
/// file-level aliases, but avoids rebuilding [`WorkspaceAliasIndex`]
/// for every unresolved RHS. The IDG workspace adapter uses this to
/// mirror function-pointer / closure aliases from the callgraph
/// without turning large C workspaces into O(functions * decls)
/// alias-index scans.
pub fn collect_workspace_local_callable_bindings(
    global: &GlobalIndex,
) -> AHashMap<FuncId, AHashMap<String, FuncId>> {
    let alias_index = WorkspaceAliasIndex::build(global);
    let empty_file_alias_targets: AHashMap<String, AliasTarget> = AHashMap::new();
    let mut out: AHashMap<FuncId, AHashMap<String, FuncId>> = AHashMap::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let alias_targets = alias_targets_for_decl(&empty_file_alias_targets, decl);
            let bindings = collect_local_callable_bindings_with_alias_index(
                &decl.flow_events,
                global,
                decl,
                &alias_targets,
                &alias_index,
            );
            if !bindings.is_empty() {
                out.insert(FuncId::new(decl.symbol.raw()), bindings);
            }
        }
    }
    out
}

pub fn collect_local_callable_bindings_with_aliases(
    events: &[FlowEvent],
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> AHashMap<String, FuncId> {
    let mut bindings = AHashMap::new();
    collect_local_callable_bindings_into(events, global, caller_decl, alias_targets, None, &mut bindings);
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
) -> AHashMap<String, FuncId> {
    let mut bindings = AHashMap::new();
    collect_local_callable_bindings_into(
        events,
        global,
        caller_decl,
        alias_targets,
        Some(alias_index),
        &mut bindings,
    );
    bindings
}

fn collect_local_callable_bindings_into(
    events: &[FlowEvent],
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    alias_index: Option<&WorkspaceAliasIndex>,
    bindings: &mut AHashMap<String, FuncId>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                value_kind,
                ..
            } => {
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
                    ) {
                        bindings.insert(target.clone(), sym);
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
                            )
                        })
                    })
                {
                    bindings.insert(target.clone(), sym);
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
                    bindings,
                );
                collect_local_callable_bindings_into(
                    else_events,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
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
                    bindings,
                );
                collect_local_callable_bindings_into(
                    catch_events,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
                    bindings,
                );
                collect_local_callable_bindings_into(
                    finally_events,
                    global,
                    caller_decl,
                    alias_targets,
                    alias_index,
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
                    bindings,
                );
            }
            _ => {}
        }
    }
}

fn resolve_returned_lambda_factory_with_alias_index(
    global: &GlobalIndex,
    raw: &str,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    alias_index: Option<&WorkspaceAliasIndex>,
) -> Option<FuncId> {
    let factory =
        resolve_callable_symbol_with_alias_index(global, raw, caller_decl, alias_targets, alias_index)?;
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

fn collect_return_spans(events: &[FlowEvent], out: &mut Vec<Span>) {
    for event in events {
        match event {
            FlowEvent::Return { span, .. } => out.push(*span),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_return_spans(then_events, out);
                collect_return_spans(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_return_spans(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_return_spans(body, out);
                collect_return_spans(catch_events, out);
                collect_return_spans(finally_events, out);
            }
            _ => {}
        }
    }
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
/// `Some(&idx)`; standalone callers (legacy taint engine, individual
/// `dump-resolve` lookups) pass `None` and pay the O(decls) scan that
/// the helper falls back to.
fn resolve_callable_symbol_with_alias_index(
    global: &GlobalIndex,
    raw: &str,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    alias_index: Option<&WorkspaceAliasIndex>,
) -> Option<FuncId> {
    let variants = callable_reference_variants(raw);
    if variants.is_empty() {
        return None;
    }
    let original_alias_qualified = variants.iter().any(|variant| {
        let trimmed = variant.trim().trim_start_matches(bonsai_common::REFERENCE_SIGILS);
        alias_target_qualified_name(trimmed, alias_targets)
    });
    let caller_file = caller_decl_file(global, caller_decl)?;
    let caller_module = caller_decl.module_path.clone();
    let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(alias_targets);
    let owned_index: Option<WorkspaceAliasIndex> = if alias_index.is_none() {
        Some(WorkspaceAliasIndex::build(global))
    } else {
        None
    };
    let alias_index: &WorkspaceAliasIndex = alias_index
        .or(owned_index.as_ref())
        .expect("alias_index built above when not supplied");
    for variant in variants {
        let trimmed = variant.trim().trim_start_matches(bonsai_common::REFERENCE_SIGILS);
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
                    AliasTarget::Namespace { module } => is_workspace_alias_target(alias_index, module),
                    AliasTarget::Member { module, member } => {
                        is_workspace_alias_target(alias_index, module)
                            || is_workspace_alias_target(alias_index, member)
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
    receiver: Option<&str>,
    receiver_types: &[String],
    call_kind: CallKind,
    call_name: &str,
    call_span: Span,
) -> Vec<FuncId> {
    if call_kind != CallKind::Method {
        return Vec::new();
    }
    let Some(receiver) = receiver else {
        return Vec::new();
    };
    let method_name = short_callee(call_name);
    if is_super_receiver(receiver) {
        return collect_super_method_targets(global, caller_decl, alias_targets, method_name);
    }
    let assigned_type_names =
        assigned_receiver_type_names(global, caller_decl, alias_targets, receiver, Some(call_span));
    let mut receiver_type_names = if assigned_type_names.is_empty() {
        receiver_types.to_vec()
    } else {
        assigned_type_names
    };
    for type_name in receiver_type_names_for_expr(caller_decl, alias_targets, receiver) {
        push_unique_string(&mut receiver_type_names, type_name);
    }
    for type_name in receiver_class_type_names_for_expr(global, caller_decl, alias_targets, receiver) {
        push_unique_string(&mut receiver_type_names, type_name);
    }
    for type_name in
        receiver_call_return_type_names(global, caller_decl, alias_targets, receiver, Some(call_span))
    {
        push_unique_string(&mut receiver_type_names, type_name);
    }
    if receiver_type_names.is_empty() {
        return Vec::new();
    }
    let caller_module = caller_decl.module_path.clone();
    // Without a known caller file we have nothing to narrow on, so
    // return empty rather than fan out to every workspace-wide
    // bare-name match.
    let (class_candidates, ctx): (Vec<SymbolId>, Option<ResolveContext<'_>>) =
        if let Some(caller_file) = caller_decl_file(global, caller_decl) {
            let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(alias_targets);
            receiver_type_names = prune_receiver_type_names_for_dispatch(receiver_type_names, global, &ctx);
            let mut seen = AHashSet::new();
            let mut classes = Vec::new();
            for receiver_type in receiver_type_names {
                for class_sym in resolve_class(global, &receiver_type, &ctx) {
                    if seen.insert(class_sym) {
                        classes.push(class_sym);
                    }
                }
            }
            (classes, Some(ctx))
        } else {
            (Vec::new(), None)
        };
    let Some(ctx) = ctx.as_ref() else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    let mut seen = AHashSet::new();
    for class_sym in class_candidates {
        collect_method_candidates_for_class(global, class_sym, method_name, ctx, &mut seen, &mut targets);
    }
    targets
}

fn collect_super_method_targets(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    method_name: &str,
) -> Vec<FuncId> {
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let Some(class_decl) = enclosing_class_for_decl(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    let mut targets = Vec::new();
    let mut seen = AHashSet::new();
    for base in &class_decl.bases {
        for class_sym in resolve_class(global, base, &ctx) {
            collect_method_candidates_for_class(
                global,
                class_sym,
                method_name,
                &ctx,
                &mut seen,
                &mut targets,
            );
        }
    }
    targets
}

fn collect_type_qualified_method_targets(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    call_name: &str,
) -> Vec<FuncId> {
    let Some((type_name, method_name)) = type_qualified_method_tail(call_name) else {
        return Vec::new();
    };
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    let class_candidates = resolve_class(global, type_name, &ctx);
    if class_candidates.is_empty() {
        return Vec::new();
    }
    let mut targets = Vec::new();
    let mut seen = AHashSet::new();
    for class_sym in class_candidates {
        collect_method_candidates_for_class(global, class_sym, method_name, &ctx, &mut seen, &mut targets);
    }
    targets
}

fn collect_constructor_targets_for_class_call(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    call_name: &str,
) -> Vec<FuncId> {
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    let mut class_candidates = resolve_class(global, call_name, &ctx);
    if class_candidates.is_empty() {
        let short = short_callee(call_name);
        if short != call_name {
            class_candidates = resolve_class(global, short, &ctx);
        }
    }
    if class_candidates.is_empty() {
        return Vec::new();
    }

    let mut targets = Vec::new();
    let mut seen = AHashSet::new();
    for class_sym in class_candidates {
        let Some(class_decl) = global.decl_of(class_sym) else {
            continue;
        };
        for method_name in [
            class_decl.name.as_str(),
            "__init__",
            "constructor",
            "__construct",
            "init",
            "new",
        ] {
            collect_method_candidates_for_class(
                global,
                class_sym,
                method_name,
                &ctx,
                &mut seen,
                &mut targets,
            );
        }
    }
    targets
}

fn type_qualified_method_tail(call_name: &str) -> Option<(&str, &str)> {
    let (head, tail) = call_name
        .rsplit_once("::")
        .or_else(|| call_name.rsplit_once('.'))?;
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
    receiver: &str,
    _call_span: Option<Span>,
) -> Vec<String> {
    let Some(inner_call) = receiver_inner_call_name(receiver) else {
        return Vec::new();
    };
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    let mut funcs = Vec::new();
    let mut late_static_type: Option<String> = None;
    if let Some(receiver_name) = receiver_name_from_call_name(&inner_call) {
        let receiver_type = short_callee(receiver_name).trim_end_matches("()");
        if !receiver_type.is_empty() {
            late_static_type = Some(receiver_type.to_string());
        }
        let method_name = callee_without_call_args(short_callee(&inner_call));
        if !receiver_type.is_empty() && !resolve_class(global, receiver_type, &ctx).is_empty() {
            let mut seen = AHashSet::new();
            for class_sym in resolve_class(global, receiver_type, &ctx) {
                collect_method_candidates_for_class(
                    global,
                    class_sym,
                    method_name,
                    &ctx,
                    &mut seen,
                    &mut funcs,
                );
            }
        }
    } else {
        for func in resolve_callable_with_context(global, &inner_call, &ctx) {
            push_unique_func(&mut funcs, func);
        }
    }
    let mut out = Vec::new();
    for func in funcs {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        collect_constructed_return_type_names(
            global,
            caller_decl,
            alias_targets,
            decl,
            late_static_type.as_deref(),
            &mut out,
        );
    }
    out
}

/// Extract the inner call name from a `Foo.bar(args)`-shaped
/// receiver, returning `Foo.bar`. Mirrors
/// `bonsai_taint::inter::receiver_inner_call_name` shape-for-shape;
/// the only difference is the normalisation helper — see
/// [`normalize_receiver_alias_text`] for why callgraph's variant is
/// the structured-input simpler form.
fn receiver_inner_call_name(receiver: &str) -> Option<String> {
    let receiver = normalize_receiver_alias_text(receiver);
    let receiver = receiver.trim();
    if !receiver.ends_with(')') {
        return None;
    }
    let open = receiver.find('(')?;
    let callee = receiver[..open].trim();
    if callee.is_empty() || callee.contains('"') || callee.contains('\'') || callee.contains('`') {
        return None;
    }
    Some(callee.to_string())
}

fn receiver_name_from_call_name(call_name: &str) -> Option<&str> {
    call_name
        .rsplit_once('.')
        .or_else(|| call_name.rsplit_once("::"))
        .or_else(|| call_name.rsplit_once("->"))
        .map(|(receiver, _)| receiver.trim())
        .filter(|receiver| !receiver.is_empty())
}

fn folded_call_name_receiver_is_instance(call_name: &str, receiver: &str, receiver_types: &[String]) -> bool {
    let receiver = normalize_receiver_alias_text(receiver);
    let bare = short_callee(&receiver);
    matches!(bare, "super" | "parent" | "base")
        || (call_name.contains("::") && !receiver_types.is_empty() && matches!(bare, "self" | "static"))
        || (!call_name.contains("::") && matches!(bare, "self" | "this"))
        || (!call_name.contains("::")
            && (receiver.starts_with("self.")
                || receiver.starts_with("this.")
                || receiver.starts_with("super.")
                || receiver.starts_with("parent.")
                || receiver.starts_with("base.")))
}

fn collect_constructed_return_type_names(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    decl: &Decl,
    late_static_type: Option<&str>,
    out: &mut Vec<String>,
) {
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return;
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    collect_constructed_return_type_names_from_events(
        global,
        &ctx,
        decl,
        late_static_type,
        &decl.flow_events,
        out,
    );
}

fn collect_constructed_return_type_names_from_events(
    global: &GlobalIndex,
    ctx: &ResolveContext<'_>,
    decl: &Decl,
    late_static_type: Option<&str>,
    events: &[FlowEvent],
    out: &mut Vec<String>,
) {
    for event in events {
        match event {
            FlowEvent::Return {
                value_text: Some(value_text),
                ..
            } => {
                if let Some(type_name) = constructed_return_type_from_text(global, ctx, value_text) {
                    push_unique_string(out, type_name);
                } else if bonsai_common::value_text_returns_self_constructor(value_text) {
                    if let Some(type_name) = late_static_type {
                        push_unique_string(out, type_name.to_string());
                    } else if let Some(parent) = decl.parent.and_then(|symbol| global.decl_of(symbol)) {
                        push_unique_string(out, parent.name.clone());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_constructed_return_type_names_from_events(
                    global,
                    ctx,
                    decl,
                    late_static_type,
                    then_events,
                    out,
                );
                collect_constructed_return_type_names_from_events(
                    global,
                    ctx,
                    decl,
                    late_static_type,
                    else_events,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_constructed_return_type_names_from_events(
                    global,
                    ctx,
                    decl,
                    late_static_type,
                    body,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_constructed_return_type_names_from_events(
                    global,
                    ctx,
                    decl,
                    late_static_type,
                    body,
                    out,
                );
                collect_constructed_return_type_names_from_events(
                    global,
                    ctx,
                    decl,
                    late_static_type,
                    catch_events,
                    out,
                );
                collect_constructed_return_type_names_from_events(
                    global,
                    ctx,
                    decl,
                    late_static_type,
                    finally_events,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn constructed_return_type_from_text(
    global: &GlobalIndex,
    ctx: &ResolveContext<'_>,
    value_text: &str,
) -> Option<String> {
    let mut text = value_text.trim();
    for keyword in bonsai_common::VALUE_TEXT_LEADING_KEYWORDS {
        text = text.strip_prefix(*keyword).unwrap_or(text).trim();
    }
    let candidate = text
        .split(['(', '{', '[', ' ', '\t', '\r', '\n'])
        .next()
        .unwrap_or(text)
        .trim();
    if candidate.is_empty()
        || !short_callee(candidate)
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
    {
        return None;
    }
    (!resolve_class(global, candidate, ctx).is_empty()).then(|| short_callee(candidate).to_string())
}

fn type_alias_for_receiver<'a>(decl: &'a Decl, receiver: &str) -> Option<&'a str> {
    let normalized = normalize_receiver_alias_text(receiver);
    let tail = short_callee(&normalized);
    let self_tail = format!("self.{tail}");
    let this_tail = format!("this.{tail}");
    decl.type_aliases
        .iter()
        .find(|alias| {
            alias.name == receiver
                || alias.name == normalized
                || alias.name == tail
                || alias.name == self_tail
                || alias.name == this_tail
        })
        .map(|alias| alias.type_name.as_str())
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
    let normalized = normalize_receiver_alias_text(receiver);
    let tail = short_callee(&normalized);
    let self_tail = format!("self.{tail}");
    let this_tail = format!("this.{tail}");
    for key in [
        receiver,
        normalized.as_str(),
        tail,
        self_tail.as_str(),
        this_tail.as_str(),
    ] {
        if let Some(AliasTarget::Type { type_name }) = alias_targets.get(key) {
            push_unique_string(&mut out, type_name.clone());
        }
    }
    out
}

fn receiver_class_type_names_for_expr(
    global: &GlobalIndex,
    decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    receiver: &str,
) -> Vec<String> {
    let Some(caller_file) = caller_decl_file(global, decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &decl.module_path).with_alias_map(alias_targets);
    let normalized = normalize_receiver_alias_text(receiver);
    let tail = short_callee(&normalized);
    let mut out = Vec::new();
    for candidate in [receiver.trim(), normalized.as_str(), tail] {
        if candidate.is_empty() {
            continue;
        }
        if !resolve_class(global, candidate, &ctx).is_empty() {
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
        &mut out,
        &mut best_distance,
    );
    out
}

fn retain_assigned_receiver_method_candidates(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    receiver: Option<&str>,
    call_span: Span,
    candidates: &mut Vec<FuncId>,
) {
    if candidates.len() <= 1 {
        return;
    }
    let Some(receiver) = receiver else {
        return;
    };
    let assigned =
        assigned_receiver_type_names(global, caller_decl, alias_targets, receiver, Some(call_span));
    if assigned.is_empty() {
        return;
    }
    let mut narrowed = Vec::new();
    for func in candidates.iter().copied() {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        let Some(class_decl) = enclosing_class_for_decl(global, decl) else {
            continue;
        };
        if assigned
            .iter()
            .any(|type_name| type_name_matches(type_name, &class_decl.name))
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
    if is_super_receiver(&receiver) {
        return;
    }
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        candidates.clear();
        return;
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(path_for_file);
    let mut receiver_class_symbols = semantic_receiver_class_symbols(
        global,
        caller_decl,
        alias_targets,
        &ctx,
        &receiver,
        receiver_types,
        call_span,
    );
    dedup_symbols(&mut receiver_class_symbols);
    candidates.retain(|func| {
        let sym = SymbolId::new(func.raw());
        let Some(decl) = global.decl_of(sym) else {
            return false;
        };
        let Some(file) = global.declaring_file(sym) else {
            return false;
        };
        if receiver_matches_decl_module(&receiver, decl, file, path_for_file) {
            return true;
        }
        receiver_class_symbols
            .iter()
            .any(|class_sym| method_decl_reachable_from_receiver_class(global, decl, *class_sym))
    });
}

fn semantic_receiver_class_symbols(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    ctx: &ResolveContext<'_>,
    receiver: &str,
    receiver_types: &[String],
    call_span: Span,
) -> Vec<SymbolId> {
    let mut type_names =
        assigned_receiver_type_names(global, caller_decl, alias_targets, receiver, Some(call_span));
    for type_name in receiver_types {
        push_unique_string(&mut type_names, type_name.clone());
    }
    for type_name in receiver_type_names_for_expr(caller_decl, alias_targets, receiver) {
        push_unique_string(&mut type_names, type_name);
    }
    for type_name in receiver_class_type_names_for_expr(global, caller_decl, alias_targets, receiver) {
        push_unique_string(&mut type_names, type_name);
    }
    for type_name in
        receiver_call_return_type_names(global, caller_decl, alias_targets, receiver, Some(call_span))
    {
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
) -> bool {
    module_target_matches_decl_module_path(receiver, &decl.module_path)
        || path_for_file(file).is_some_and(|path| module_target_matches_path(receiver, &path))
}

fn method_decl_reachable_from_receiver_class(
    global: &GlobalIndex,
    method_decl: &Decl,
    receiver_class: SymbolId,
) -> bool {
    let Some(method_parent) = method_decl.parent else {
        return false;
    };
    if method_parent == receiver_class {
        return true;
    }
    let mut seen = AHashSet::new();
    let mut stack = vec![receiver_class];
    while let Some(class_sym) = stack.pop() {
        if !seen.insert(class_sym) {
            continue;
        }
        let Some(class_decl) = global.decl_of(class_sym) else {
            continue;
        };
        let Some(class_file) = global.declaring_file(class_sym) else {
            continue;
        };
        let base_ctx = ResolveContext::new(class_file, &class_decl.module_path);
        for base in &class_decl.bases {
            for base_sym in resolve_class(global, base, &base_ctx) {
                if base_sym == method_parent {
                    return true;
                }
                stack.push(base_sym);
            }
        }
    }
    false
}

fn retain_assigned_receiver_constructor_candidates(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    assign_span: &Span,
    candidates: &mut Vec<FuncId>,
) {
    if candidates.len() <= 1 {
        return;
    }
    let assigned = assigned_receiver_type_names(global, caller_decl, alias_targets, "", Some(*assign_span));
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
            .any(|type_name| type_name_matches(type_name, &class_decl.name))
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
                if !receiver.is_empty() && normalize_receiver_alias_text(target) != receiver {
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
                    ) {
                        push_assigned_receiver_type(out, best_distance, type_name, distance);
                    }
                }
                for candidate in source_call
                    .iter()
                    .chain(source_name.iter())
                    .chain(source_names.iter())
                {
                    let candidate = normalize_receiver_alias_text(candidate);
                    if call_name_looks_type_constructor(&candidate)
                        && class_like_constructor_call(global, caller_decl, alias_targets, &candidate)
                    {
                        push_assigned_receiver_type(
                            out,
                            best_distance,
                            short_callee(&candidate).to_string(),
                            distance,
                        );
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

fn call_name_looks_type_constructor(name: &str) -> bool {
    short_callee(name)
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
}

fn class_like_constructor_call(
    global: &GlobalIndex,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    callee_name: &str,
) -> bool {
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return false;
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    if !resolve_class(global, callee_name, &ctx).is_empty() {
        return true;
    }
    let tail = short_callee(callee_name);
    tail != callee_name && !resolve_class(global, tail, &ctx).is_empty()
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
/// reference sigils (`&str`, `*const T`), and rewrites C/C++/PHP
/// `->` member access to `.` form.
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
    text.trim_start_matches(bonsai_common::REFERENCE_SIGILS)
        .replace("->", ".")
        .trim()
        .trim_matches('.')
        .to_string()
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

fn colon_remote_call(name: &str) -> bool {
    name.contains(':') && !name.contains("::")
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
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((head, tail)) = trimmed.rsplit_once("::") {
        if !head.is_empty() && !tail.is_empty() {
            return Some((head, tail));
        }
    }
    if let Some((head, tail)) = trimmed.rsplit_once('.') {
        if !head.is_empty() && !tail.is_empty() {
            return Some((head, tail));
        }
    }
    if let Some((head, tail)) = trimmed.rsplit_once(':') {
        if !head.is_empty() && !tail.is_empty() {
            return Some((head, tail));
        }
    }
    if let Some((head, tail)) = trimmed.rsplit_once('\\') {
        if !head.is_empty() && !tail.is_empty() {
            return Some((head, tail));
        }
    }
    None
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
    caller_export_aliases: &[&'static str],
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Vec<FuncId> {
    if alias_target.is_empty() || alias_tail.is_empty() {
        return Vec::new();
    }
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let caller_ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    let mut seen_spans = AHashSet::new();
    let mut targets = Vec::new();
    for func in export_name_variants(alias_tail, caller_export_aliases)
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
        let semantic_match = module_target_matches_decl_module_path(alias_target, &decl.module_path);
        let in_target_file = semantic_match
            || path_for_file(file).is_some_and(|path| module_target_matches_path(alias_target, &path));
        if !in_target_file {
            continue;
        }
        if seen_spans.insert((file, decl.span.start, decl.span.end)) {
            targets.push(func);
        }
    }
    targets
}

#[allow(clippy::too_many_arguments)] // mirrors collect_workspace_module_targets
fn collect_workspace_targets_for_alias_entry(
    global: &GlobalIndex,
    alias_target: &AliasTarget,
    alias_tail: &str,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
    caller_export_aliases: &[&'static str],
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Vec<FuncId> {
    match alias_target {
        AliasTarget::Namespace { module } => collect_workspace_module_targets(
            global,
            module,
            alias_tail,
            path_for_file,
            caller_export_aliases,
            caller_decl,
            alias_targets,
        ),
        AliasTarget::Member { module, member } => {
            let mut targets = collect_workspace_module_targets(
                global,
                module,
                alias_tail,
                path_for_file,
                caller_export_aliases,
                caller_decl,
                alias_targets,
            );
            if targets.is_empty() {
                targets = collect_workspace_module_targets(
                    global,
                    member,
                    alias_tail,
                    path_for_file,
                    caller_export_aliases,
                    caller_decl,
                    alias_targets,
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
    caller_export_aliases: &[&'static str],
    caller_decl: &Decl,
) -> Vec<FuncId> {
    if let Some((alias_target, alias_tail)) = namespace_alias_target_tail(name, alias_targets) {
        let candidates = collect_workspace_module_targets(
            global,
            alias_target,
            alias_tail,
            path_for_file,
            caller_export_aliases,
            caller_decl,
            alias_targets,
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
            caller_export_aliases,
            caller_decl,
            alias_targets,
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
            caller_export_aliases,
            caller_decl,
            alias_targets,
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
            caller_export_aliases,
            caller_decl,
            alias_targets,
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
    let mut targets = collect_callable_targets_exact(global, name);
    // Ruby method names ending in `!` are aliases for the bare-name
    // version on the same receiver; retry without the suffix.
    if targets.is_empty() {
        if let Some(no_bang) = name.strip_suffix('!') {
            targets = collect_callable_targets_exact(global, no_bang);
        }
    }
    targets
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
    collect_callable_targets_with_context_aliases_and_paths(global, name, caller_decl, alias_targets, &|_| {
        None
    })
}

fn collect_callable_targets_with_context_aliases_and_paths(
    global: &GlobalIndex,
    name: &str,
    caller_decl: &Decl,
    alias_targets: &AHashMap<String, AliasTarget>,
    path_for_file: &dyn Fn(FileId) -> Option<String>,
) -> Vec<FuncId> {
    let mut targets = collect_implicit_receiver_method_targets(global, caller_decl, name);
    if !targets.is_empty() {
        return targets;
    }
    let Some(caller_file) = caller_decl_file(global, caller_decl) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(path_for_file);
    targets = resolve_callable_with_context(global, name, &ctx);
    if targets.is_empty() {
        if let Some(no_bang) = name.strip_suffix('!') {
            targets = resolve_callable_with_context(global, no_bang, &ctx);
        }
    }
    targets
}

fn collect_c_linked_callable_targets(
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

fn c_family_linked_language(language: Option<&'static str>) -> bool {
    matches!(language, Some("c" | "cpp" | "objc"))
}

fn collect_implicit_receiver_method_targets(
    global: &GlobalIndex,
    caller_decl: &Decl,
    name: &str,
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
    let mut targets = Vec::new();
    let mut seen = AHashSet::new();
    // CONTEXTLESS_LOOKUP_JUSTIFICATION: implicit receiver dispatch is
    // narrowed by exact parent SymbolId before emitting any edge. This
    // is equivalent to looking up methods on the caller's enclosing
    // class/trait, not a workspace-wide bare-name call resolution.
    for symbol in global.find_by_name(name) {
        let Some(decl) = global.decl_of(*symbol) else {
            continue;
        };
        if decl.parent != Some(parent) {
            continue;
        }
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let func = FuncId::new(decl.symbol.raw());
        if seen.insert(func) {
            targets.push(func);
        }
    }
    targets
}

fn implicit_receiver_call_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && !trimmed.contains('.')
        && !trimmed.contains("::")
        && !trimmed.contains(':')
        && !trimmed.contains('\\')
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
    caller_export_aliases: &[&'static str],
) -> Vec<FuncId> {
    let folded_receiver = receiver_name_from_call_name(name)
        .filter(|candidate| folded_call_name_receiver_is_instance(name, candidate, receiver_types));
    let semantic_receiver = receiver.or(folded_receiver);
    let mut targets = if semantic_receiver.is_none() {
        collect_nested_local_callable_targets(global, caller_decl, name, call_span)
    } else {
        Vec::new()
    };
    if targets.is_empty() {
        targets = collect_receiver_method_targets(
            global,
            caller_decl,
            alias_targets,
            semantic_receiver,
            receiver_types,
            call_kind,
            name,
            call_span,
        );
    }
    if targets.is_empty() {
        targets = collect_type_qualified_method_targets(global, caller_decl, alias_targets, name);
    }
    let typed_receiver_method = semantic_receiver.is_some() && !receiver_types.is_empty();
    if targets.is_empty() && !typed_receiver_method {
        targets = collect_qualified_workspace_targets(
            global,
            name,
            None,
            alias_targets,
            path_for_file,
            caller_export_aliases,
            caller_decl,
        );
    }
    let unresolved_method_receiver =
        targets.is_empty() && call_kind == CallKind::Method && semantic_receiver.is_some();
    let local_value_shadow = semantic_receiver.is_none()
        && local_value_binding_shadows_callable(&caller_decl.flow_events, name, call_span);
    if targets.is_empty() && !unresolved_method_receiver && !local_value_shadow {
        targets = collect_callable_targets_with_context_aliases_and_paths(
            global,
            name,
            caller_decl,
            alias_targets,
            path_for_file,
        );
    }
    if targets.is_empty() && !unresolved_method_receiver && !local_value_shadow {
        let short = short_callee(name);
        // For Rust-style `Type::method` qualified calls, allow the
        // bare-tail fallback ONLY when the qualifier resolves to
        // an in-workspace alias. See the matching guard at the
        // build-time call site above for the full rationale.
        // The legacy taint engine still routes through this entry
        // and doesn't share the callgraph build's WorkspaceAliasIndex,
        // so we build a local one — call-frequency here is bounded
        // by the legacy engine's per-source pass.
        let local_alias_index = WorkspaceAliasIndex::build(global);
        let allow_short_fallback = if let Some(idx) = name.find("::") {
            let qualifier = &name[..idx];
            alias_targets
                .get(qualifier)
                .map(|t| match t {
                    AliasTarget::Namespace { module } => {
                        is_workspace_alias_target(&local_alias_index, module)
                    }
                    AliasTarget::Member { module, member } => {
                        is_workspace_alias_target(&local_alias_index, module)
                            || is_workspace_alias_target(&local_alias_index, member)
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
                alias_targets,
                path_for_file,
            );
        }
    }
    if !targets.is_empty() {
        retain_assigned_receiver_method_candidates(
            global,
            caller_decl,
            alias_targets,
            semantic_receiver,
            call_span,
            &mut targets,
        );
        let receiver_supplied = semantic_receiver.is_some() || call_kind == CallKind::Method;
        retain_signature_compatible_candidates(global, caller_decl, &mut targets, args, receiver_supplied);
    }
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
/// * `class_names` — every `DeclKind::Class` decl's bare name.
///   Covers `AliasTarget::Type` rebindings (`let r: Repository`)
///   and Rust-style `Foo::method` where `Foo` is a user struct.
/// * `module_canonicals` — every decl's `module_path.segments`
///   joined with both `::` and `.` separators, so alias targets
///   spelled `crate::storage`, `storage`, or `app.storage` all
///   resolve. Stored as `(canonical, leading_segment)` so the
///   suffix-match in `is_workspace_alias_target` doesn't have to
///   call `ends_with(&format!(...))` per candidate.
#[derive(Default)]
struct WorkspaceAliasIndex {
    class_names: ahash::AHashSet<String>,
    /// Pairs of (canonical_module_path, language_separator).
    /// canonical is the joined module path, separator is `::` or
    /// `.` depending on which form the adapter records.
    module_canonicals: ahash::AHashSet<String>,
}

impl WorkspaceAliasIndex {
    fn build(global: &GlobalIndex) -> Self {
        let mut class_names: ahash::AHashSet<String> = ahash::AHashSet::default();
        let mut module_canonicals: ahash::AHashSet<String> = ahash::AHashSet::default();
        for file in global.all_files() {
            for decl in global.decls_in(file) {
                if matches!(decl.kind, DeclKind::Class) {
                    class_names.insert(decl.name.clone());
                }
                if !decl.module_path.is_empty() {
                    let segs = &decl.module_path.segments;
                    module_canonicals.insert(segs.join("::"));
                    module_canonicals.insert(segs.join("."));
                }
            }
        }
        Self {
            class_names,
            module_canonicals,
        }
    }

    fn contains(&self, module: &str) -> bool {
        let trimmed = module.trim();
        if trimmed.is_empty() {
            return false;
        }
        if self.class_names.contains(trimmed) {
            return true;
        }
        let stripped = trimmed.trim_start_matches("crate::").trim_start_matches("crate.");
        if self.module_canonicals.contains(trimmed) || self.module_canonicals.contains(stripped) {
            return true;
        }
        // Suffix-match: alias targets like `app` should also hit
        // `crate::app` / `pkg.app.sub`. Iterate the precomputed
        // canonical set and check ::trimmed / .trimmed suffixes.
        // O(canonicals) but bounded by file count, not decl count,
        // and each contains-check is hash-table-fast.
        let needle_cc = format!("::{trimmed}");
        let needle_dot = format!(".{trimmed}");
        let needle_cc_stripped = format!("::{stripped}");
        let needle_dot_stripped = format!(".{stripped}");
        for canonical in &self.module_canonicals {
            if canonical.ends_with(&needle_cc)
                || canonical.ends_with(&needle_dot)
                || canonical.ends_with(&needle_cc_stripped)
                || canonical.ends_with(&needle_dot_stripped)
            {
                return true;
            }
        }
        false
    }
}

/// True when `module` names something the workspace recognises —
/// either a known module path or a declared type / class name.
/// Memoised against a precomputed [`WorkspaceAliasIndex`] so the
/// short-tail gate is O(1) per call instead of O(decls). See the
/// index's docs for the rationale.
fn is_workspace_alias_target(idx: &WorkspaceAliasIndex, module: &str) -> bool {
    idx.contains(module)
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
    let short = short_qualified_tail(call_name);
    if local_bindings
        .get(call_name)
        .or_else(|| local_bindings.get(short))
        .is_some_and(|func| *func == target_func)
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
    if call_resolves_to_func(global, aliases, local_bindings, caller_decl, name, target_func) {
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
