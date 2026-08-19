//! Debug-dump command data layer (`dump-hir`, `dump-cfg`,
//! `dump-callgraph`, `dump-edges`, `dump-resolve`, `dump-taint`,
//! `dump-ast`). The data extraction lives here; the CLI binary
//! renders the structured results.

use crate::common::{format_span, workspace_relative_path};
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::FuncId;
use bonsai_lang_api::{Decl, DeclKind, FlowEvent};
use bonsai_workspace::Workspace;
use serde::Serialize;
use std::path::Path;

/// `dump-hir` payload: the decl header + its full flow-event tree.
/// Mirrors the JSON the CLI emits.
#[derive(Serialize, Clone, Debug)]
pub struct HirDump {
    pub analysis_complete: bool,
    pub analysis_incomplete_reasons: Vec<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualified_name: Option<String>,
    pub kind: String,
    pub params: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub param_annotations: Vec<Vec<String>>,
    /// Direct parameter-default calls as exact adapter-emitted syntax facts.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub param_default_calls: Vec<Vec<String>>,
    /// Adapter-emitted receiver/type bindings consumed by resolver and
    /// callgraph narrowing. Including these in the HIR dump makes a bad edge
    /// diagnosable from compiler facts instead of requiring ad-hoc logging.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub type_aliases: Vec<bonsai_lang_api::TypeAliasBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_type: Option<String>,
    pub span: bonsai_common::Span,
    pub body_span: Option<bonsai_common::Span>,
    /// Compile-time lexical bindings visible to the callable but not
    /// executed as part of its body (for example Java `static final`
    /// literal fields).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub lexical_context: Vec<FlowEvent>,
    pub flow_events: Vec<FlowEvent>,
}

impl HirDump {
    /// Lift a [`Decl`] into the externally-serialised HIR shape.
    fn from_decl(decl: &Decl) -> Self {
        let (lexical_context, flow_events) = partition_decl_events(decl);
        Self {
            // `dump-hir` is a local structural dump of the adapter-emitted
            // declaration body; no resolver fan-out or flow solve is involved.
            analysis_complete: true,
            analysis_incomplete_reasons: Vec::new(),
            name: decl.name.clone(),
            qualified_name: decl.qualified_name.clone(),
            kind: format!("{:?}", decl.kind).to_lowercase(),
            params: decl.params.clone(),
            param_annotations: decl.param_annotations.clone(),
            param_default_calls: decl.param_default_calls.clone(),
            type_aliases: decl.type_aliases.clone(),
            return_type: decl.return_type.clone(),
            span: decl.span,
            body_span: decl.body_span,
            lexical_context,
            flow_events,
        }
    }
}

fn partition_decl_events(decl: &Decl) -> (Vec<FlowEvent>, Vec<FlowEvent>) {
    let Some(body) = decl.body_span else {
        return (Vec::new(), decl.flow_events.clone());
    };
    decl.flow_events.iter().cloned().partition(|event| {
        let span = event.span();
        span.file != body.file || span.start < body.start || body.end < span.end
    })
}

fn runtime_flow_events(decl: &Decl) -> Vec<FlowEvent> {
    partition_decl_events(decl).1
}

#[derive(Serialize, Clone, Debug)]
pub struct DumpCallableCandidate {
    pub func_id: u32,
    pub name: String,
    pub kind: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub disambiguator: String,
}

#[derive(Clone, Debug)]
pub struct DumpLookupError {
    pub symbol: String,
    pub candidates: Vec<DumpCallableCandidate>,
}

impl std::fmt::Display for DumpLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "dump target `{}` is ambiguous ({} callable decls). Use path:name or path:line:name.",
            self.symbol,
            self.candidates.len()
        )?;
        for candidate in self.candidates.iter().take(12) {
            writeln!(
                f,
                "  {}:{}:{} {}  disambiguator: {}",
                candidate.file, candidate.line, candidate.column, candidate.name, candidate.disambiguator
            )?;
        }
        if self.candidates.len() > 12 {
            writeln!(f, "  ... {} more candidate(s)", self.candidates.len() - 12)?;
        }
        Ok(())
    }
}

impl std::error::Error for DumpLookupError {}

/// Fetch the HIR (`flow_events` tree + decl header) for one callable.
/// Bare names must resolve to exactly one callable; use `path:name` or
/// `path:line:name` when a workspace has same-named functions.
pub fn dump_hir(ws: &Workspace, symbol: &str) -> Result<Option<HirDump>, DumpLookupError> {
    resolve_single_callable(ws, symbol).map(|decl| decl.map(|d| HirDump::from_decl(&d)))
}

/// Build the basic-block CFG for one callable. Bare names must resolve
/// to exactly one callable; use `path:name` or `path:line:name` when a
/// workspace has same-named functions.
pub fn dump_cfg(ws: &Workspace, symbol: &str) -> Result<Option<bonsai_cfg::Cfg>, DumpLookupError> {
    let Some(decl) = resolve_single_callable(ws, symbol)? else {
        return Ok(None);
    };
    Ok(Some(bonsai_cfg::build_cfg_from_flow(
        &decl.name,
        &runtime_flow_events(&decl),
    )))
}

/// One row in the `dump-callgraph` table: a function with its
/// semantic caller-function count and semantic outgoing-callee count.
#[derive(Serialize, Clone, Debug)]
pub struct CallgraphRow {
    pub function: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualified_name: Option<String>,
    pub file: String,
    pub name_start: u64,
    pub callers: usize,
    pub outgoing: usize,
}

impl CallgraphRow {
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.qualified_name.as_deref().unwrap_or(&self.function)
    }
}

/// Build the per-function callers / outgoing summary, sorted
/// hottest-first (most callers, then most outgoing, then alpha).
pub fn dump_callgraph(ws: &Workspace) -> Vec<CallgraphRow> {
    callgraph_summary(ws, &ws.cached_resolved_call_graph())
}

/// Variant of [`dump_callgraph`] that takes a pre-built resolved
/// call graph. Useful when the caller already has one in hand
/// (e.g. through `bonsai_inspect::ChainCache::resolved_graph`).
pub fn callgraph_summary(ws: &Workspace, resolved: &ResolvedCallGraph) -> Vec<CallgraphRow> {
    use rayon::prelude::*;
    let global = ws.compiler_header_index();
    let files: Vec<_> = global.all_files().collect();
    let mut rows: Vec<CallgraphRow> = files
        .par_iter()
        .flat_map_iter(|&file| {
            let mut per_file: Vec<CallgraphRow> = Vec::new();
            for func_decl in global.functions_in(file) {
                let func = bonsai_common::FuncId::new(func_decl.symbol.raw());
                let caller_count = unique_semantic_callers(resolved, func).len();
                let outgoing_count = unique_semantic_callees(resolved, func).len();
                per_file.push(CallgraphRow {
                    function: func_decl.name.clone(),
                    qualified_name: func_decl.qualified_name.clone(),
                    file: ws.vfs().path(file).map_or_else(
                        |_| "<unknown>".to_string(),
                        |path| workspace_relative_path(ws, &path.display().to_string()),
                    ),
                    name_start: func_decl.name_span.start,
                    callers: caller_count,
                    outgoing: outgoing_count,
                });
            }
            per_file.into_iter()
        })
        .collect();
    // Hottest first: most callers, then most outgoing, alpha tiebreak.
    rows.sort_by(|a, b| {
        b.callers
            .cmp(&a.callers)
            .then_with(|| b.outgoing.cmp(&a.outgoing))
            .then_with(|| a.display_name().cmp(b.display_name()))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.name_start.cmp(&b.name_start))
    });
    rows
}

fn unique_semantic_callers(resolved: &ResolvedCallGraph, func: FuncId) -> Vec<FuncId> {
    let mut callers: Vec<FuncId> = resolved
        .callers_of(func)
        .filter(|edge| edge.precision.is_semantic())
        .map(|edge| edge.from)
        .collect();
    callers.sort_by_key(|caller| caller.raw());
    callers.dedup();
    callers
}

fn unique_semantic_callees(resolved: &ResolvedCallGraph, func: FuncId) -> Vec<FuncId> {
    let mut callees: Vec<FuncId> = resolved
        .callees_of(func)
        .filter(|edge| edge.precision.is_semantic())
        .map(|edge| edge.to)
        .collect();
    callees.sort_by_key(|callee| callee.raw());
    callees.dedup();
    callees
}

#[derive(Debug, Default)]
struct CallableSpec<'a> {
    file: Option<&'a str>,
    line: Option<u32>,
    name: &'a str,
}

fn split_callable_spec(spec: &str) -> CallableSpec<'_> {
    let Some(name_idx) = spec.rfind(':') else {
        return CallableSpec {
            name: spec,
            ..Default::default()
        };
    };
    let (head, name) = (&spec[..name_idx], &spec[name_idx + 1..]);
    if name.is_empty() || head.is_empty() || name.contains(['/', '\\']) {
        return CallableSpec {
            name: spec,
            ..Default::default()
        };
    }
    let path_like = |value: &str| value.contains(['/', '\\']);
    if let Some((path, maybe_line)) = head.rsplit_once(':') {
        if !path.is_empty() {
            if let Ok(line) = maybe_line.parse::<u32>() {
                return CallableSpec {
                    file: Some(path),
                    line: Some(line),
                    name,
                };
            }
        }
    }
    if path_like(head) {
        return CallableSpec {
            file: Some(head),
            line: None,
            name,
        };
    }
    CallableSpec {
        name: spec,
        ..Default::default()
    }
}

/// Return the exact file qualifier carried by a dump target, if any.
///
/// CLI and SDK opening strategies use this same parser as callable
/// resolution so scoped commands cannot disagree about forms such as
/// `json.lua:189:codepoint_to_utf8`.
#[must_use]
pub fn dump_callable_file_qualifier(spec: &str) -> Option<&str> {
    split_callable_spec(spec).file
}

/// Resolve `symbol` to exactly one function / method / constructor decl.
/// Context-free lookup is acceptable here only as an inventory step:
/// multiple candidates are returned as ambiguity instead of silently
/// choosing one.
fn resolve_single_callable(ws: &Workspace, symbol: &str) -> Result<Option<Decl>, DumpLookupError> {
    let spec = split_callable_spec(symbol);
    let global = ws.compiler_header_index();
    let vfs = ws.db().vfs();
    let wanted_segments = bonsai_common::qualified_name_segments(spec.name);
    let lookup_name = wanted_segments.last().copied().unwrap_or(spec.name);
    let qualified_query = wanted_segments.len() > 1;
    let mut candidates: Vec<Decl> = global
        .find_by_name(lookup_name)
        .iter()
        .filter_map(|symbol| global.decl_of(*symbol))
        .filter(|decl| {
            if !qualified_query {
                return decl.name == spec.name;
            }
            decl.qualified_name.as_deref().is_some_and(|qualified| {
                let observed = bonsai_common::qualified_name_segments(qualified);
                observed.len() >= wanted_segments.len()
                    && observed[observed.len() - wanted_segments.len()..] == wanted_segments[..]
            })
        })
        .map(|decl| FuncId::new(decl.symbol.raw()))
        .filter_map(|func| {
            ws.exact_frontend_decl(bonsai_common::SymbolId::new(func.raw()))
                .map(|decl| (*decl).clone())
        })
        .filter(|decl| {
            matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            )
        })
        .filter(|decl| {
            let (file, line, _) = format_span(&decl.name_span, ws);
            spec.file.is_none_or(|qualifier| {
                file_matches_qualifier(&file, qualifier, ws.db().workspace_root().as_deref())
            }) && spec.line.is_none_or(|wanted| line == wanted)
        })
        .collect();
    candidates.sort_by(|a, b| {
        let a_path = vfs
            .path(a.span.file)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let b_path = vfs
            .path(b.span.file)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        a_path
            .cmp(&b_path)
            .then_with(|| a.name_span.start.cmp(&b.name_span.start))
            .then_with(|| a.symbol.raw().cmp(&b.symbol.raw()))
    });
    match candidates.len() {
        0 => Ok(None),
        1 => Ok(candidates.into_iter().next()),
        _ => Err(DumpLookupError {
            symbol: symbol.to_string(),
            candidates: candidates.iter().map(|decl| dump_candidate(ws, decl)).collect(),
        }),
    }
}

fn file_matches_qualifier(decl_file: &str, qualifier: &str, workspace_root: Option<&Path>) -> bool {
    if decl_file == qualifier {
        return true;
    }
    let decl_path = Path::new(decl_file);
    let rooted_decl = workspace_root
        .filter(|_| !decl_path.is_absolute())
        .map_or_else(|| decl_path.to_path_buf(), |root| root.join(decl_path));
    let canonical_decl = rooted_decl
        .canonicalize()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let canonical_qualifier = Path::new(qualifier)
        .canonicalize()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    if canonical_decl
        .as_deref()
        .zip(canonical_qualifier.as_deref())
        .is_some_and(|(decl, qual)| decl == qual)
    {
        return true;
    }
    if decl_file.ends_with(qualifier)
        && decl_file
            .as_bytes()
            .get(decl_file.len().saturating_sub(qualifier.len()).saturating_sub(1))
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

fn dump_candidate(ws: &Workspace, decl: &Decl) -> DumpCallableCandidate {
    let (file, line, column) = format_span(&decl.name_span, ws);
    DumpCallableCandidate {
        func_id: decl.symbol.raw(),
        name: decl.name.clone(),
        kind: format!("{:?}", decl.kind).to_lowercase(),
        disambiguator: format!("{file}:{line}:{}", decl.name),
        file,
        line,
        column,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_line_name_is_file_qualified_callable() {
        let spec = split_callable_spec("json.lua:189:codepoint_to_utf8");
        assert_eq!(spec.file, Some("json.lua"));
        assert_eq!(spec.line, Some(189));
        assert_eq!(spec.name, "codepoint_to_utf8");
    }

    #[test]
    fn module_style_colon_without_line_stays_bare_callable_name() {
        let spec = split_callable_spec("My.Module:run");
        assert_eq!(spec.file, None);
        assert_eq!(spec.line, None);
        assert_eq!(spec.name, "My.Module:run");
    }

    #[test]
    fn hir_separates_lexical_bindings_from_runtime_body_events() {
        let file = bonsai_common::FileId::new(1);
        let lexical = FlowEvent::Assign {
            span: bonsai_common::Span::new(file, 10, 20),
            target: "ALG".to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: false,
            value_kind: Some(bonsai_lang_api::AssignValueKind::Literal),
        };
        let runtime = FlowEvent::Call {
            span: bonsai_common::Span::new(file, 110, 120),
            name: "sink".to_string(),
            receiver: None,
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: Vec::new(),
        };
        let decl = Decl {
            symbol: bonsai_common::SymbolId::new(1),
            kind: DeclKind::Method,
            name: "run".to_string(),
            qualified_name: Some("App.run".to_string()),
            module_path: bonsai_lang_api::ModulePath::default(),
            span: bonsai_common::Span::new(file, 90, 140),
            name_span: bonsai_common::Span::new(file, 90, 93),
            visibility: bonsai_lang_api::Visibility::Public,
            parent: None,
            body_span: Some(bonsai_common::Span::new(file, 100, 140)),
            flow_events: vec![lexical.clone(), runtime.clone()],
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            param_default_calls: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            receiver_field_initializers: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        };

        let dump = HirDump::from_decl(&decl);

        assert_eq!(dump.qualified_name.as_deref(), Some("App.run"));
        assert_eq!(dump.lexical_context, vec![lexical]);
        assert_eq!(dump.flow_events, vec![runtime]);
        assert_eq!(runtime_flow_events(&decl), dump.flow_events);
    }
}
