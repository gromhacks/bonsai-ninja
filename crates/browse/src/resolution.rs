//! Resolution coverage data layer.
//!
//! This is a language-agnostic view over the shared adapter contract:
//! `FlowEvent::Call` is the syntax-derived call-site fact and
//! `ResolvedCallGraph` is the canonical semantic edge source. The
//! collector never falls back to text search or language-specific
//! heuristics.

use crate::common::{file_path_matches_filter, format_span};
use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::EdgeKind;
use bonsai_common::{FuncId, Span};
use bonsai_lang_api::{AliasTarget, CallKind, Decl, DeclKind, FlowEvent};
use bonsai_workspace::Workspace;
use serde::Serialize;

/// Filter bundle for [`resolution_coverage`].
#[derive(Copy, Clone, Default, Debug)]
pub struct ResolutionCoverageFilters<'a> {
    /// Keep only rows whose workspace-relative file path matches this text.
    /// Explicit absolute paths are also accepted.
    pub file: Option<&'a str>,
    /// Keep only rows with at least one unresolved call site.
    pub unresolved_only: bool,
}

/// Resolution coverage report for one file.
#[derive(Serialize, Clone, Debug, Default)]
pub struct ResolutionCoverageFileRow {
    pub file: String,
    pub functions: usize,
    pub call_sites: usize,
    pub resolved_call_sites: usize,
    pub unresolved_call_sites: usize,
    pub direct_edges: usize,
    pub virtual_edges: usize,
    pub indirect_edges: usize,
    pub dynamic_call_sites: usize,
    pub macro_call_sites: usize,
    pub external_call_sites: usize,
    pub receiver_type_gaps: usize,
    pub coverage_percent: f64,
    pub analysis_complete: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub analysis_incomplete_reasons: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub decls: Vec<ResolutionCoverageDeclRow>,
}

/// Resolution coverage report for one function/method/constructor.
#[derive(Serialize, Clone, Debug, Default)]
pub struct ResolutionCoverageDeclRow {
    pub name: String,
    pub kind: String,
    pub line: u32,
    pub call_sites: usize,
    pub resolved_call_sites: usize,
    pub unresolved_call_sites: usize,
    pub direct_edges: usize,
    pub virtual_edges: usize,
    pub indirect_edges: usize,
    pub dynamic_call_sites: usize,
    pub macro_call_sites: usize,
    pub external_call_sites: usize,
    pub receiver_type_gaps: usize,
    pub coverage_percent: f64,
    pub analysis_complete: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub analysis_incomplete_reasons: Vec<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
struct CallSiteKey {
    func: FuncId,
    file: bonsai_common::FileId,
    start: u64,
    end: u64,
}

impl CallSiteKey {
    fn new(func: FuncId, span: Span) -> Self {
        Self {
            func,
            file: span.file,
            start: span.start,
            end: span.end,
        }
    }
}

#[derive(Copy, Clone, Debug, Default)]
struct EdgeCounts {
    direct: usize,
    virtual_edges: usize,
    indirect: usize,
}

/// Build per-file/per-decl call resolution coverage from shared HIR
/// call-site facts and the canonical resolved call graph.
#[must_use]
pub fn resolution_coverage(
    ws: &Workspace,
    filters: &ResolutionCoverageFilters<'_>,
) -> Vec<ResolutionCoverageFileRow> {
    let global = ws.db().global_index();
    let resolved = ws.resolved_call_graph();
    let mut resolved_sites: AHashMap<CallSiteKey, EdgeCounts> = AHashMap::new();
    for edge in resolved
        .inner()
        .edges
        .iter()
        .filter(|edge| edge.precision.is_semantic())
    {
        let key = CallSiteKey::new(edge.from, edge.span);
        let counts = resolved_sites.entry(key).or_default();
        match edge.kind {
            EdgeKind::Direct => counts.direct += 1,
            EdgeKind::Virtual => counts.virtual_edges += 1,
            EdgeKind::Indirect => counts.indirect += 1,
            EdgeKind::Unknown => {}
        }
    }

    let mut rows = Vec::new();
    for file in global.all_files() {
        let Ok(path) = ws.vfs().path(file) else {
            continue;
        };
        let file_path = path.to_string_lossy().to_string();
        if filters
            .file
            .is_some_and(|needle| !file_path_matches_filter(ws, &file_path, needle))
        {
            continue;
        }
        let mut file_row = ResolutionCoverageFileRow {
            file: file_path,
            ..ResolutionCoverageFileRow::default()
        };
        let file_alias_targets: AHashMap<String, AliasTarget> =
            bonsai_lang_api::alias_map_from_import_specs(&ws.db().imports_for(file))
                .into_iter()
                .collect();
        for decl in global.decls_in(file) {
            if !is_callable_decl(decl.kind) {
                continue;
            }
            let decl_row = coverage_for_decl(ws, decl, &resolved_sites, &file_alias_targets);
            file_row.functions += 1;
            file_row.call_sites += decl_row.call_sites;
            file_row.resolved_call_sites += decl_row.resolved_call_sites;
            file_row.unresolved_call_sites += decl_row.unresolved_call_sites;
            file_row.direct_edges += decl_row.direct_edges;
            file_row.virtual_edges += decl_row.virtual_edges;
            file_row.indirect_edges += decl_row.indirect_edges;
            file_row.dynamic_call_sites += decl_row.dynamic_call_sites;
            file_row.macro_call_sites += decl_row.macro_call_sites;
            file_row.external_call_sites += decl_row.external_call_sites;
            file_row.receiver_type_gaps += decl_row.receiver_type_gaps;
            file_row.decls.push(decl_row);
        }
        finalize_file_row(&mut file_row);
        if filters.unresolved_only && file_row.unresolved_call_sites == 0 {
            continue;
        }
        rows.push(file_row);
    }
    rows.sort_by(|a, b| {
        b.unresolved_call_sites
            .cmp(&a.unresolved_call_sites)
            .then_with(|| a.file.cmp(&b.file))
    });
    rows
}

fn coverage_for_decl(
    ws: &Workspace,
    decl: &Decl,
    resolved_sites: &AHashMap<CallSiteKey, EdgeCounts>,
    file_alias_targets: &AHashMap<String, AliasTarget>,
) -> ResolutionCoverageDeclRow {
    let (_, line, _) = format_span(&decl.name_span, ws);
    let mut row = ResolutionCoverageDeclRow {
        name: decl.name.clone(),
        kind: format!("{:?}", decl.kind).to_lowercase(),
        line,
        ..ResolutionCoverageDeclRow::default()
    };
    let mut alias_targets = file_alias_targets.clone();
    bonsai_lang_api::extend_alias_map_with_flow_events(&mut alias_targets, &decl.flow_events);
    let mut seen_sites: AHashSet<CallSiteKey> = AHashSet::default();
    let mut external_receivers: AHashSet<String> = AHashSet::default();
    collect_decl_call_sites(
        ws,
        decl,
        &decl.flow_events,
        resolved_sites,
        &alias_targets,
        &mut external_receivers,
        &mut seen_sites,
        &mut row,
    );
    finalize_decl_row(&mut row);
    row
}

#[allow(clippy::too_many_arguments)] // cohesive per-decl call-site scan state
fn collect_decl_call_sites(
    ws: &Workspace,
    decl: &Decl,
    events: &[FlowEvent],
    resolved_sites: &AHashMap<CallSiteKey, EdgeCounts>,
    alias_targets: &AHashMap<String, AliasTarget>,
    external_receivers: &mut AHashSet<String>,
    seen_sites: &mut AHashSet<CallSiteKey>,
    row: &mut ResolutionCoverageDeclRow,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types,
                call_kind,
                ..
            } => {
                let key = CallSiteKey::new(FuncId::new(decl.symbol.raw()), *span);
                if !seen_sites.insert(key) {
                    continue;
                }
                row.call_sites += 1;
                let resolved_counts = resolved_sites.get(&key);
                let known_external = resolved_counts.is_none()
                    && known_external_call_site(
                        ws,
                        name,
                        receiver.as_deref(),
                        alias_targets,
                        external_receivers,
                    );
                if matches!(call_kind, CallKind::Indirect) {
                    row.dynamic_call_sites += 1;
                }
                if matches!(call_kind, CallKind::Macro) {
                    row.macro_call_sites += 1;
                }
                if resolved_counts.is_none()
                    && !known_external
                    && matches!(call_kind, CallKind::Method | CallKind::Constructor)
                    && receiver.is_some()
                    && receiver_types.is_empty()
                {
                    row.receiver_type_gaps += 1;
                }
                if let Some(counts) = resolved_counts {
                    row.resolved_call_sites += 1;
                    row.direct_edges += counts.direct;
                    row.virtual_edges += counts.virtual_edges;
                    row.indirect_edges += counts.indirect;
                } else if known_external {
                    row.external_call_sites += 1;
                } else {
                    row.unresolved_call_sites += 1;
                }
            }
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                ..
            } => {
                if let Some(target) = simple_local_target(target) {
                    let external_source_call = source_call.as_deref().is_some_and(|call| {
                        known_external_call_site(
                            ws,
                            call,
                            receiver_name_from_call_name(call),
                            alias_targets,
                            external_receivers,
                        )
                    });
                    let external_source_name = source_name
                        .as_deref()
                        .and_then(simple_local_binding)
                        .is_some_and(|name| external_receivers.contains(name))
                        || source_names
                            .iter()
                            .filter_map(|name| simple_local_binding(name))
                            .any(|name| external_receivers.contains(name));
                    if external_source_call || external_source_name {
                        external_receivers.insert(target.to_string());
                    } else {
                        external_receivers.remove(target);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                let mut then_external = external_receivers.clone();
                collect_decl_call_sites(
                    ws,
                    decl,
                    then_events,
                    resolved_sites,
                    alias_targets,
                    &mut then_external,
                    seen_sites,
                    row,
                );
                let mut else_external = external_receivers.clone();
                collect_decl_call_sites(
                    ws,
                    decl,
                    else_events,
                    resolved_sites,
                    alias_targets,
                    &mut else_external,
                    seen_sites,
                    row,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                let mut body_external = external_receivers.clone();
                collect_decl_call_sites(
                    ws,
                    decl,
                    body,
                    resolved_sites,
                    alias_targets,
                    &mut body_external,
                    seen_sites,
                    row,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                let mut body_external = external_receivers.clone();
                collect_decl_call_sites(
                    ws,
                    decl,
                    body,
                    resolved_sites,
                    alias_targets,
                    &mut body_external,
                    seen_sites,
                    row,
                );
                let mut catch_external = external_receivers.clone();
                collect_decl_call_sites(
                    ws,
                    decl,
                    catch_events,
                    resolved_sites,
                    alias_targets,
                    &mut catch_external,
                    seen_sites,
                    row,
                );
                let mut finally_external = external_receivers.clone();
                collect_decl_call_sites(
                    ws,
                    decl,
                    finally_events,
                    resolved_sites,
                    alias_targets,
                    &mut finally_external,
                    seen_sites,
                    row,
                );
            }
            _ => {}
        }
    }
}

fn finalize_file_row(row: &mut ResolutionCoverageFileRow) {
    row.coverage_percent = coverage_percent(row.resolved_call_sites, workspace_resolution_sites(row));
    row.analysis_incomplete_reasons = incomplete_reasons(
        row.unresolved_call_sites,
        row.dynamic_call_sites,
        row.macro_call_sites,
        row.receiver_type_gaps,
    );
    row.analysis_complete = row.analysis_incomplete_reasons.is_empty();
}

fn finalize_decl_row(row: &mut ResolutionCoverageDeclRow) {
    row.coverage_percent = coverage_percent(row.resolved_call_sites, workspace_resolution_sites(row));
    row.analysis_incomplete_reasons = incomplete_reasons(
        row.unresolved_call_sites,
        row.dynamic_call_sites,
        row.macro_call_sites,
        row.receiver_type_gaps,
    );
    row.analysis_complete = row.analysis_incomplete_reasons.is_empty();
}

fn coverage_percent(resolved: usize, total: usize) -> f64 {
    if total == 0 {
        100.0
    } else {
        (resolved as f64 / total as f64 * 1000.0).round() / 10.0
    }
}

trait ResolutionCoverageCounts {
    fn resolved_call_sites(&self) -> usize;
    fn unresolved_call_sites(&self) -> usize;
}

impl ResolutionCoverageCounts for ResolutionCoverageFileRow {
    fn resolved_call_sites(&self) -> usize {
        self.resolved_call_sites
    }

    fn unresolved_call_sites(&self) -> usize {
        self.unresolved_call_sites
    }
}

impl ResolutionCoverageCounts for ResolutionCoverageDeclRow {
    fn resolved_call_sites(&self) -> usize {
        self.resolved_call_sites
    }

    fn unresolved_call_sites(&self) -> usize {
        self.unresolved_call_sites
    }
}

fn workspace_resolution_sites(row: &impl ResolutionCoverageCounts) -> usize {
    row.resolved_call_sites() + row.unresolved_call_sites()
}

fn incomplete_reasons(
    unresolved_call_sites: usize,
    dynamic_call_sites: usize,
    macro_call_sites: usize,
    receiver_type_gaps: usize,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if unresolved_call_sites > 0 {
        reasons.push(format!("unresolved call sites: {unresolved_call_sites}"));
    }
    if dynamic_call_sites > 0 {
        reasons.push(format!("dynamic call sites: {dynamic_call_sites}"));
    }
    if macro_call_sites > 0 {
        reasons.push(format!("macro call sites: {macro_call_sites}"));
    }
    if receiver_type_gaps > 0 {
        reasons.push(format!("receiver type gaps: {receiver_type_gaps}"));
    }
    reasons
}

fn is_callable_decl(kind: DeclKind) -> bool {
    matches!(
        kind,
        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
    )
}

fn known_external_call_site(
    ws: &Workspace,
    name: &str,
    receiver: Option<&str>,
    alias_targets: &AHashMap<String, AliasTarget>,
    external_receivers: &AHashSet<String>,
) -> bool {
    if receiver
        .and_then(simple_local_binding)
        .is_some_and(|receiver| external_receivers.contains(receiver))
    {
        return true;
    }
    if receiver
        .and_then(|receiver| receiver_alias_head(receiver, name))
        .or_else(|| call_alias_head(name))
        .is_some_and(|head| alias_target_is_external_workspace_miss(ws, head, alias_targets))
    {
        return true;
    }
    call_alias_head(name).is_some_and(|head| {
        alias_targets
            .get(head)
            .is_some_and(|target| alias_target_is_external(ws, target))
    })
}

fn alias_target_is_external_workspace_miss(
    ws: &Workspace,
    head: &str,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> bool {
    alias_targets
        .get(head)
        .is_some_and(|target| alias_target_is_external(ws, target))
}

fn alias_target_is_external(ws: &Workspace, target: &AliasTarget) -> bool {
    match target {
        AliasTarget::Namespace { module } => !module_may_target_workspace(ws, module),
        AliasTarget::Member { module, member } => {
            !module_may_target_workspace(ws, module) && !module_may_target_workspace(ws, member)
        }
        AliasTarget::Type { .. } => false,
    }
}

fn module_may_target_workspace(ws: &Workspace, module: &str) -> bool {
    let Some(module_key) = normalize_module_key(module) else {
        return false;
    };
    let module_tail = module_key.rsplit('/').next().unwrap_or(module_key.as_str());
    for file in ws.db().global_index().all_files() {
        let Ok(path) = ws.vfs().path(file) else {
            continue;
        };
        let file_key = normalize_file_key(&path.to_string_lossy());
        if file_key == module_key
            || file_key.ends_with(&format!("/{module_key}"))
            || (!module_tail.is_empty() && file_key.rsplit('/').next() == Some(module_tail))
        {
            return true;
        }
    }
    false
}

fn normalize_module_key(module: &str) -> Option<String> {
    let trimmed = module
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'))
        .trim_start_matches('.')
        .trim_end_matches(['/', '\\'])
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    // `::` first so a scope separator collapses to a single `/`, then the
    // remaining single-char separators together.
    let mut out = trimmed.replace("::", "/").replace(['\\', ':', '.'], "/");
    out = strip_known_extension(&out).to_string();
    Some(
        out.split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .collect::<Vec<_>>()
            .join("/"),
    )
    .filter(|key| !key.is_empty())
}

fn normalize_file_key(path: &str) -> String {
    let path = path.replace('\\', "/");
    let stripped = strip_known_extension(&path);
    stripped
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/")
}

fn strip_known_extension(path: &str) -> &str {
    const EXTS: &[&str] = &[
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".scala", ".go", ".rs", ".c", ".h", ".cc",
        ".cpp", ".cxx", ".hpp", ".cs", ".rb", ".php", ".swift", ".dart", ".ex", ".exs", ".erl", ".hrl",
        ".lua", ".pl", ".pm", ".m", ".mm", ".sol",
    ];
    EXTS.iter().find_map(|ext| path.strip_suffix(ext)).unwrap_or(path)
}

fn receiver_name_from_call_name(name: &str) -> Option<&str> {
    name.rsplit_once(['.', ':']).map(|(receiver, _)| receiver.trim())
}

fn call_alias_head(name: &str) -> Option<&str> {
    simple_local_binding(name.split(['.', ':', '/', '\\']).next().unwrap_or(name))
}

fn receiver_alias_head<'a>(receiver: &'a str, name: &'a str) -> Option<&'a str> {
    simple_local_binding(receiver).or_else(|| call_alias_head(name))
}

fn simple_local_binding(text: &str) -> Option<&str> {
    let trimmed = text.trim().trim_start_matches(bonsai_common::REFERENCE_SIGILS);
    let mut chars = trimmed.char_indices();
    let (_, first) = chars.next()?;
    if !(first == '_' || first == '$' || first.is_ascii_alphabetic()) {
        return None;
    }
    for (idx, ch) in chars {
        if !(ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()) {
            return (idx > 0).then_some(&trimmed[..idx]);
        }
    }
    Some(trimmed)
}

fn simple_local_target(text: &str) -> Option<&str> {
    let trimmed = text.trim().trim_start_matches(bonsai_common::REFERENCE_SIGILS);
    let binding = simple_local_binding(trimmed)?;
    (binding.len() == trimmed.len()).then_some(binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_workspace::Workspace;

    #[test]
    fn completion_flag_matches_reported_gap_reasons() {
        let mut decl = ResolutionCoverageDeclRow {
            call_sites: 2,
            resolved_call_sites: 2,
            dynamic_call_sites: 1,
            macro_call_sites: 1,
            ..ResolutionCoverageDeclRow::default()
        };
        finalize_decl_row(&mut decl);

        assert!((decl.coverage_percent - 100.0).abs() < f64::EPSILON);
        assert!(
            !decl.analysis_complete,
            "dynamic/macro gaps must not report complete analysis: {decl:#?}"
        );
        assert!(
            decl.analysis_incomplete_reasons
                .iter()
                .any(|reason| reason == "dynamic call sites: 1"),
            "dynamic gap missing from reasons: {decl:#?}"
        );
        assert!(
            decl.analysis_incomplete_reasons
                .iter()
                .any(|reason| reason == "macro call sites: 1"),
            "macro gap missing from reasons: {decl:#?}"
        );

        let mut file = ResolutionCoverageFileRow {
            call_sites: 1,
            resolved_call_sites: 1,
            receiver_type_gaps: 1,
            ..ResolutionCoverageFileRow::default()
        };
        finalize_file_row(&mut file);

        assert!(
            !file.analysis_complete,
            "file completion should be false whenever reasons are reported: {file:#?}"
        );
        assert_eq!(
            file.analysis_complete,
            file.analysis_incomplete_reasons.is_empty()
        );
    }

    #[test]
    fn imported_external_receiver_chains_are_not_receiver_type_gaps() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            r#"
import os
import sqlite3

def load():
    conn = sqlite3.connect("auth.db")
    cursor = conn.cursor()
    cursor.execute("select 1")
    os.system("id")
"#,
        )
        .expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let rows = resolution_coverage(&ws, &ResolutionCoverageFilters::default());
        let row = rows
            .iter()
            .find(|row| row.file.ends_with("app.py"))
            .expect("app.py row");

        assert_eq!(row.call_sites, 4, "fixture call count changed: {row:#?}");
        assert_eq!(
            row.external_call_sites, 4,
            "imported module calls and receiver chains from them should be external: {row:#?}"
        );
        assert_eq!(
            row.receiver_type_gaps, 0,
            "external API receiver chains must not masquerade as workspace receiver-type gaps: {row:#?}"
        );
        assert_eq!(row.unresolved_call_sites, 0, "{row:#?}");
        assert!(
            row.analysis_complete,
            "known external calls are not incomplete workspace resolution: {row:#?}"
        );
        assert!((row.coverage_percent - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn unresolved_local_receiver_methods_remain_receiver_type_gaps() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("app.py"),
            r#"
def local_gap(obj):
    obj.run()
"#,
        )
        .expect("write fixture");
        let ws =
            Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

        let rows = resolution_coverage(&ws, &ResolutionCoverageFilters::default());
        let row = rows
            .iter()
            .find(|row| row.file.ends_with("app.py"))
            .expect("app.py row");

        assert_eq!(row.call_sites, 1, "{row:#?}");
        assert_eq!(row.external_call_sites, 0, "{row:#?}");
        assert_eq!(row.unresolved_call_sites, 1, "{row:#?}");
        assert_eq!(
            row.receiver_type_gaps, 1,
            "unknown local receivers should still be reported as receiver-type gaps: {row:#?}"
        );
        assert!(
            !row.analysis_complete,
            "true receiver-type gaps must keep analysis_complete false: {row:#?}"
        );
        assert!((row.coverage_percent - 0.0).abs() < f64::EPSILON);
    }
}
