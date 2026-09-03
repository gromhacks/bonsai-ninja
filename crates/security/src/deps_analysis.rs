//! Dependency usage analysis.
//!
//! `security deps` answers "which flagged packages are present?". This module
//! answers "where is each of them used?": the import sites that bring the
//! dependency in, the local names those imports bind (`serialize` in
//! `const serialize = require("node-serialize")`, `S` in `use X\Service as S`),
//! every call or reference that reaches the dependency through one of those
//! names, and every rulepack source / sink / sanitizer match whose rule claims
//! the dependency. Each site carries its enclosing callable, and each callable
//! carries its resolved direct callers from the cached compiler call graph, so
//! a reviewer can triage dependency code without running taint analysis.
//!
//! The analysis is a single pass over the exact per-file compiler objects plus
//! one lookup per callable in the cached resolved call graph. It never
//! enumerates call paths.

use crate::analysis::{
    dependency_inventory, sanitizer_inventory, sink_inventory, source_inventory, DependencyInventoryOptions,
    SecurityInventoryOptions,
};
use crate::deps::{import_package_candidates, DependencyRow};
use crate::loader::Rulepack;
use crate::matcher::RuleMatch;
use ahash::{AHashMap, AHashSet};
use anyhow::Result;
use bonsai_common::{FileId, FuncId, Span, SymbolId};
use bonsai_lang_api::{Decl, FlowEvent, RefKind};
use bonsai_workspace::Workspace;
use serde::Serialize;
use std::path::Path;

/// Options for [`dependency_analysis`]. Package/severity/path selectors are
/// applied to the complete inventory before usage collection.
#[derive(Clone, Debug, Default)]
pub struct DependencyAnalysisOptions {
    pub inventory: DependencyInventoryOptions,
}

/// One place a dependency is imported, bound, used, or matched by a rule.
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DependencyUsageSite {
    pub file: String,
    pub line: u32,
    pub column: u32,
    /// `import` (the import statement), `call` (a call through a bound
    /// name), `ref` (a non-call reference to a bound name), or the rule
    /// family of a rulepack match: `source`, `sink`, `sanitizer`.
    pub kind: String,
    /// Module text, callee text, referenced name, or rule match text.
    pub text: String,
    /// Enclosing callable display name; `None` at module scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_function: Option<String>,
    /// Local name through which a call/ref reached the dependency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_alias: Option<String>,
    /// Rule id for rulepack matches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip)]
    pub in_func: Option<FuncId>,
}

/// A callable that touches the dependency and its resolved direct callers.
#[derive(Clone, Debug, Serialize)]
pub struct DependencyFunctionRow {
    pub function: String,
    pub file: String,
    pub line: u32,
    /// Number of usage sites inside this callable.
    pub site_count: usize,
    /// Display names of resolved direct callers (`Owner.member` when the
    /// workspace has same-named callables). Empty when nothing resolved
    /// calls the function.
    pub direct_callers: Vec<String>,
    #[serde(skip)]
    pub func: FuncId,
}

/// One dependency with every place it is used.
#[derive(Clone, Debug, Serialize)]
pub struct DependencyAnalysisCandidate {
    pub dependency: DependencyRow,
    /// Local names bound to the dependency by import statements, sorted.
    pub bound_names: Vec<String>,
    pub sites: Vec<DependencyUsageSite>,
    pub functions: Vec<DependencyFunctionRow>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DependencyAnalysisReport {
    pub candidates: Vec<DependencyAnalysisCandidate>,
    pub analysis_complete: bool,
    pub analysis_incomplete_reasons: Vec<String>,
}

/// Build the dependency usage report for the (already filtered) inventory.
pub fn dependency_analysis(
    ws: &Workspace,
    pack: &Rulepack,
    root: &Path,
    options: DependencyAnalysisOptions,
) -> Result<DependencyAnalysisReport> {
    let inventory = dependency_inventory(ws, pack, root, options.inventory.clone());
    if inventory.rows.is_empty() {
        let analysis_incomplete_reasons = Vec::new();
        return Ok(DependencyAnalysisReport {
            candidates: Vec::new(),
            analysis_complete: analysis_incomplete_reasons.is_empty(),
            analysis_incomplete_reasons,
        });
    }
    let inventory_options = SecurityInventoryOptions {
        files: options.inventory.files.clone(),
        exclude_files: options.inventory.exclude_files.clone(),
        ..SecurityInventoryOptions::default()
    };
    let mut matches_by_rule: AHashMap<String, Vec<(&'static str, RuleMatch)>> = AHashMap::new();
    for (family, matches) in [
        ("source", source_inventory(ws, pack, inventory_options.clone())?),
        ("sink", sink_inventory(ws, pack, inventory_options.clone())?),
        ("sanitizer", sanitizer_inventory(ws, pack, inventory_options)?),
    ] {
        for matched in matches {
            matches_by_rule
                .entry(matched.rule_id.clone())
                .or_default()
                .push((family, matched));
        }
    }

    let global = ws.compiler_header_index();
    let call_graph = ws.cached_resolved_call_graph();
    let mut incomplete_reasons = Vec::new();
    let mut candidates = Vec::with_capacity(inventory.rows.len());
    for row in inventory.rows {
        let mut sites: Vec<DependencyUsageSite> = Vec::new();
        for rule_id in &row.rule_ids {
            for (family, matched) in matches_by_rule.get(rule_id).into_iter().flatten() {
                sites.push(DependencyUsageSite {
                    file: matched.file.clone(),
                    line: matched.line,
                    column: matched.column,
                    kind: (*family).to_string(),
                    text: matched.match_text.clone(),
                    in_function: matched.enclosing_fn.clone(),
                    via_alias: None,
                    rule_id: Some(matched.rule_id.clone()),
                    in_func: enclosing_func_at(ws, matched.span),
                });
            }
        }
        let usage = collect_import_usage(ws, pack, &row, &mut incomplete_reasons);
        sites.extend(usage.sites);
        sites.sort();
        sites.dedup_by(|a, b| {
            a.file == b.file && a.line == b.line && a.column == b.column && a.kind == b.kind
        });

        let mut functions: Vec<DependencyFunctionRow> = Vec::new();
        let mut seen_funcs: AHashSet<FuncId> = AHashSet::new();
        for site in &sites {
            let Some(func) = site.in_func else {
                continue;
            };
            if !seen_funcs.insert(func) {
                if let Some(existing) = functions.iter_mut().find(|row| row.func == func) {
                    existing.site_count += 1;
                }
                continue;
            }
            let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
                continue;
            };
            let (file, line, _) = crate::analysis::resolve_span_location(ws, decl.name_span);
            let mut direct_callers: Vec<String> = call_graph
                .callers_of(func)
                .map(|edge| bonsai_inspect::func_display_name(ws, edge.from))
                .collect();
            direct_callers.sort();
            direct_callers.dedup();
            functions.push(DependencyFunctionRow {
                function: bonsai_inspect::func_display_name(ws, func),
                file: bonsai_common::workspace_relative_filter_path(Some(root), &file),
                line,
                site_count: 1,
                direct_callers,
                func,
            });
        }
        functions.sort_by(|a, b| {
            (a.file.as_str(), a.line, a.function.as_str()).cmp(&(
                b.file.as_str(),
                b.line,
                b.function.as_str(),
            ))
        });
        let mut bound_names = usage.bound_names;
        bound_names.sort();
        bound_names.dedup();
        candidates.push(DependencyAnalysisCandidate {
            dependency: row,
            bound_names,
            sites,
            functions,
        });
    }
    incomplete_reasons.sort();
    incomplete_reasons.dedup();
    Ok(DependencyAnalysisReport {
        analysis_complete: incomplete_reasons.is_empty(),
        analysis_incomplete_reasons: incomplete_reasons,
        candidates,
    })
}

struct ImportUsage {
    bound_names: Vec<String>,
    sites: Vec<DependencyUsageSite>,
}

/// Import statements binding `row.key` plus every call/reference through the
/// names they bind, over the exact per-file compiler objects of `row.language`.
fn collect_import_usage(
    ws: &Workspace,
    pack: &Rulepack,
    row: &DependencyRow,
    incomplete_reasons: &mut Vec<String>,
) -> ImportUsage {
    let db = ws.db();
    let root = db.workspace_root();
    let package_matching = pack
        .metadata
        .languages
        .get(&row.language)
        .map(|metadata| metadata.package_matching.clone())
        .unwrap_or_default();
    let mut bound_names = Vec::new();
    let mut sites = Vec::new();
    for file in ws.vfs().all_files() {
        let Some(adapter) = db.adapter_for(file) else {
            continue;
        };
        if adapter.language_id().as_str() != row.language {
            continue;
        }
        let Some(object) = db.compiler_file_object_uncached(file) else {
            let path = file_display_path(ws, file);
            incomplete_reasons.push(format!(
                "dependency-analysis: compiler object unavailable for {path}"
            ));
            continue;
        };
        let Some(imports) = object.imports.as_ref() else {
            continue;
        };
        // Names this file binds to the dependency.
        let mut file_names: Vec<String> = Vec::new();
        for import in &imports.imports {
            let matches_key = import_package_candidates(&import.module, &package_matching)
                .iter()
                .any(|candidate| candidate == &row.key);
            if !matches_key {
                continue;
            }
            let (path, line, column) = crate::analysis::resolve_span_location(ws, import.span);
            let path = bonsai_common::workspace_relative_filter_path(root.as_deref(), &path);
            let mut text = import.module.clone();
            if let Some(original) = import.original_name.as_deref() {
                text = format!("{original} from {}", import.module);
            }
            if let Some(alias) = import.alias.as_deref() {
                text.push_str(&format!(" as {alias}"));
            }
            sites.push(DependencyUsageSite {
                file: path,
                line,
                column,
                kind: "import".to_string(),
                text,
                in_function: None,
                via_alias: None,
                rule_id: None,
                in_func: None,
            });
            for name in [import.alias.as_deref(), import.original_name.as_deref()]
                .into_iter()
                .flatten()
            {
                if !name.is_empty() && !file_names.iter().any(|existing| existing == name) {
                    file_names.push(name.to_string());
                }
            }
            if import.alias.is_none() && import.original_name.is_none() {
                // `import os` / `import x.y` bind the module's tail segment.
                if let Some(tail) = module_tail(&import.module) {
                    if !file_names.iter().any(|existing| existing == tail) {
                        file_names.push(tail.to_string());
                    }
                }
            }
        }
        if file_names.is_empty() {
            continue;
        }
        let Some(index) = object.declarations.as_ref() else {
            continue;
        };
        let decls: Vec<&Decl> = index.defs.iter().collect();
        let push_site =
            |kind: &str, text: &str, span: Span, alias: &str, sites: &mut Vec<DependencyUsageSite>| {
                let (path, line, column) = crate::analysis::resolve_span_location(ws, span);
                let enclosing = bonsai_inspect::find_enclosing_func(&decls, span);
                sites.push(DependencyUsageSite {
                    file: bonsai_common::workspace_relative_filter_path(root.as_deref(), &path),
                    line,
                    column,
                    kind: kind.to_string(),
                    text: text.to_string(),
                    in_function: enclosing.as_ref().map(|(_, name)| name.clone()),
                    via_alias: Some(alias.to_string()),
                    rule_id: None,
                    in_func: enclosing.map(|(func, _)| func),
                });
            };
        for decl in &decls {
            walk_calls(&decl.flow_events, &mut |name, receiver, span| {
                if let Some(alias) = bound_name_for(name, receiver, &file_names) {
                    push_site("call", name, span, alias, &mut sites);
                }
            });
        }
        for reference in &index.refs {
            if !matches!(reference.kind, RefKind::Read | RefKind::Call | RefKind::Write) {
                continue;
            }
            if let Some(alias) = bound_name_for(&reference.name, None, &file_names) {
                let kind = if reference.kind == RefKind::Call {
                    "call"
                } else {
                    "ref"
                };
                push_site(kind, &reference.name, reference.span, alias, &mut sites);
            }
        }
        bound_names.extend(file_names);
    }
    ImportUsage { bound_names, sites }
}

/// The bound name (if any) through which `callee` reaches the dependency:
/// the exact name, a `name.member` / `name::member` / `name->member` /
/// `name:member` head, or an explicit receiver equal to the name.
fn bound_name_for<'a>(callee: &str, receiver: Option<&str>, names: &'a [String]) -> Option<&'a str> {
    names.iter().map(String::as_str).find(|name| {
        callee == *name
            || receiver == Some(*name)
            || [".", "::", "->", ":"]
                .iter()
                .any(|sep| callee.starts_with(&format!("{name}{sep}")))
    })
}

fn module_tail(module: &str) -> Option<&str> {
    module
        .rsplit(['.', '/', ':', '\\'])
        .next()
        .filter(|tail| !tail.is_empty())
}

/// Visit every call event (including calls nested in branches, loops,
/// try/catch, defer/using bodies, and assignment sources).
fn walk_calls(events: &[FlowEvent], visit: &mut dyn FnMut(&str, Option<&str>, Span)) {
    for event in events {
        match event {
            FlowEvent::Call {
                name, receiver, span, ..
            } => visit(name, receiver.as_deref(), *span),
            FlowEvent::Assign {
                span, source_call, ..
            } => {
                if let Some(name) = source_call.as_deref() {
                    visit(name, None, *span);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk_calls(then_events, visit);
                walk_calls(else_events, visit);
            }
            FlowEvent::Loop {
                condition_events,
                update_events,
                body,
                ..
            } => {
                walk_calls(condition_events, visit);
                walk_calls(update_events, visit);
                walk_calls(body, visit);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk_calls(body, visit);
                walk_calls(catch_events, visit);
                walk_calls(finally_events, visit);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => walk_calls(body, visit),
            _ => {}
        }
    }
}

fn enclosing_func_at(ws: &Workspace, span: Span) -> Option<FuncId> {
    let index = ws.exact_decl_index_shared(span.file)?;
    let decls: Vec<&Decl> = index.defs.iter().collect();
    bonsai_inspect::find_enclosing_func(&decls, span).map(|(func, _)| func)
}

fn file_display_path(ws: &Workspace, file: FileId) -> String {
    ws.vfs()
        .path(file)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| format!("file#{}", file.raw()))
}
