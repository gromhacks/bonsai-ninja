//! Dependency usage analysis.
//!
//! `security deps` answers "which flagged packages are present?". This module
//! answers "where is each of them used?": the import sites that bring the
//! dependency in, the local names those imports bind (`serialize` in
//! `const serialize = require("node-serialize")`, `S` in `use X\Service as S`),
//! every call or reference that reaches the dependency through one of those
//! names, and every rulepack source / sink / sanitizer match whose rule claims
//! the dependency. Each site carries its enclosing callable. The CLI joins
//! these sites with the cached complete taint-analysis report to show the
//! taint flows each dependency appears in.
//!
//! The analysis is a single pass over the exact per-file compiler objects. It
//! never enumerates call paths.

use crate::analysis::{
    dependency_inventory, sanitizer_inventory, sink_inventory, source_inventory, DependencyInventoryOptions,
    SecurityInventoryOptions,
};
use crate::deps::{import_package_candidates, DependencyInventory, DependencyRow};
use crate::loader::Rulepack;
use crate::matcher::RuleMatch;
use ahash::AHashMap;
use anyhow::Result;
use bonsai_common::{FileId, FuncId, Span};
use bonsai_lang_api::{FlowEvent, RefKind};
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

/// One dependency with every place it is used.
#[derive(Clone, Debug, Serialize)]
pub struct DependencyAnalysisCandidate {
    pub dependency: DependencyRow,
    /// Local names bound to the dependency by import statements, sorted.
    pub bound_names: Vec<String>,
    pub sites: Vec<DependencyUsageSite>,
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
    let matches = DependencyInventoryMatches {
        sources: source_inventory(ws, pack, inventory_options.clone())?,
        sinks: sink_inventory(ws, pack, inventory_options.clone())?,
        sanitizers: sanitizer_inventory(ws, pack, inventory_options)?,
    };
    dependency_analysis_with_inventory(ws, pack, inventory, matches)
}

/// Complete source/sink/sanitizer inventories for the analysis scope.
/// Callers that already hold them (cached complete objects) pass them in so
/// the analysis is a projection, never a rescan.
#[derive(Clone, Debug, Default)]
pub struct DependencyInventoryMatches {
    pub sources: Vec<RuleMatch>,
    pub sinks: Vec<RuleMatch>,
    pub sanitizers: Vec<RuleMatch>,
}

/// [`dependency_analysis`] over precomputed inventories: same output, no
/// inventory scan.
pub fn dependency_analysis_with_matches(
    ws: &Workspace,
    pack: &Rulepack,
    root: &Path,
    options: DependencyAnalysisOptions,
    matches: DependencyInventoryMatches,
) -> Result<DependencyAnalysisReport> {
    let inventory = dependency_inventory(ws, pack, root, options.inventory);
    if inventory.rows.is_empty() {
        let analysis_incomplete_reasons = Vec::new();
        return Ok(DependencyAnalysisReport {
            candidates: Vec::new(),
            analysis_complete: analysis_incomplete_reasons.is_empty(),
            analysis_incomplete_reasons,
        });
    }
    dependency_analysis_with_inventory(ws, pack, inventory, matches)
}

fn dependency_analysis_with_inventory(
    ws: &Workspace,
    pack: &Rulepack,
    inventory: DependencyInventory,
    matches: DependencyInventoryMatches,
) -> Result<DependencyAnalysisReport> {
    let mut matches_by_rule: AHashMap<String, Vec<(&'static str, RuleMatch)>> = AHashMap::new();
    for (family, family_matches) in [
        ("source", matches.sources),
        ("sink", matches.sinks),
        ("sanitizer", matches.sanitizers),
    ] {
        for matched in family_matches {
            matches_by_rule
                .entry(matched.rule_id.clone())
                .or_default()
                .push((family, matched));
        }
    }

    let mut incomplete_reasons = Vec::new();
    let usages = collect_import_usage_for_rows(ws, pack, &inventory.rows, &mut incomplete_reasons);
    let mut candidates = Vec::with_capacity(inventory.rows.len());
    for (row, usage) in inventory.rows.into_iter().zip(usages) {
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
        sites.extend(usage.sites);
        sites.sort();
        sites.dedup_by(|a, b| {
            a.file == b.file && a.line == b.line && a.column == b.column && a.kind == b.kind
        });

        let mut bound_names = usage.bound_names;
        bound_names.sort();
        bound_names.dedup();
        candidates.push(DependencyAnalysisCandidate {
            dependency: row,
            bound_names,
            sites,
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

/// Import statements binding each package row plus every call/reference
/// through the bound names, for every row at once: each file's compiler
/// object is decoded once and its calls/refs walked once, then matched
/// against every row of the file's language. Returns one usage per row,
/// aligned with `rows`.
fn collect_import_usage_for_rows(
    ws: &Workspace,
    pack: &Rulepack,
    rows: &[DependencyRow],
    incomplete_reasons: &mut Vec<String>,
) -> Vec<ImportUsage> {
    use rayon::prelude::*;
    let db = ws.db();
    let root = db.workspace_root();
    let mut usages: Vec<ImportUsage> = rows
        .iter()
        .map(|_| ImportUsage {
            bound_names: Vec::new(),
            sites: Vec::new(),
        })
        .collect();
    let mut rows_by_language: AHashMap<&str, Vec<usize>> = AHashMap::new();
    for (index, row) in rows.iter().enumerate() {
        rows_by_language
            .entry(row.language.as_str())
            .or_default()
            .push(index);
    }
    let package_matching_by_language: AHashMap<&str, _> = rows_by_language
        .keys()
        .map(|language| {
            (
                *language,
                pack.metadata
                    .languages
                    .get(*language)
                    .map(|metadata| metadata.package_matching.clone())
                    .unwrap_or_default(),
            )
        })
        .collect();

    // Per-file result: usage sites and bound names per dependency row, plus
    // an incompleteness reason when the compiler object is unavailable.
    struct FileUsage {
        sites: Vec<(usize, DependencyUsageSite)>,
        bound_names: Vec<(usize, Vec<String>)>,
        incomplete: Option<String>,
    }

    let files = ws.vfs().all_files();
    let per_file: Vec<Option<FileUsage>> = files
        .par_iter()
        .map(|&file| {
            let adapter = db.adapter_for(file)?;
            let language = adapter.language_id().as_str();
            let row_indexes = rows_by_language.get(language)?;
            // The import header is a small, separately addressable part of
            // the compiler object; the full object (declarations, bodies) is
            // decoded only for files that import a flagged package.
            let Some(imports) = db.compiler_import_index_uncached(file) else {
                let path = file_display_path(ws, file);
                return Some(FileUsage {
                    sites: Vec::new(),
                    bound_names: Vec::new(),
                    incomplete: Some(format!(
                        "dependency-analysis: compiler object unavailable for {path}"
                    )),
                });
            };
            let package_matching = &package_matching_by_language[language];
            let import_candidates: Vec<Vec<String>> = imports
                .imports
                .iter()
                .map(|import| import_package_candidates(&import.module, package_matching))
                .collect();
            let mut out = FileUsage {
                sites: Vec::new(),
                bound_names: Vec::new(),
                incomplete: None,
            };
            let mut file_names_by_row: Vec<(usize, Vec<String>)> = Vec::new();
            for &row_index in row_indexes {
                let row = &rows[row_index];
                let mut file_names: Vec<String> = Vec::new();
                for (import, candidates) in imports.imports.iter().zip(&import_candidates) {
                    if !candidates.iter().any(|candidate| candidate == &row.key) {
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
                    out.sites.push((
                        row_index,
                        DependencyUsageSite {
                            file: path,
                            line,
                            column,
                            kind: "import".to_string(),
                            text,
                            in_function: None,
                            via_alias: None,
                            rule_id: None,
                            in_func: None,
                        },
                    ));
                    for name in [import.alias.as_deref(), import.original_name.as_deref()]
                        .into_iter()
                        .flatten()
                    {
                        if !name.is_empty() && !file_names.iter().any(|existing| existing == name) {
                            file_names.push(name.to_string());
                        }
                    }
                    if import.alias.is_none() && import.original_name.is_none() {
                        if let Some(tail) = module_tail(&import.module) {
                            if !file_names.iter().any(|existing| existing == tail) {
                                file_names.push(tail.to_string());
                            }
                        }
                    }
                }
                if !file_names.is_empty() {
                    file_names_by_row.push((row_index, file_names));
                }
            }
            if file_names_by_row.is_empty() {
                return Some(out);
            }
            let Some(object) = db.compiler_file_object_uncached(file) else {
                let path = file_display_path(ws, file);
                out.incomplete = Some(format!(
                    "dependency-analysis: compiler object unavailable for {path}"
                ));
                return Some(out);
            };
            let Some(index) = object.declarations.as_ref() else {
                return Some(out);
            };
            let enclosing_index =
                bonsai_workspace::enclosing_index::EnclosingSpanIndex::from_callable_decls(&index.defs);
            let mut calls: Vec<(String, Option<String>, Span)> = Vec::new();
            for decl in &index.defs {
                walk_calls(&decl.flow_events, &mut |name, receiver, span| {
                    calls.push((name.to_string(), receiver.map(str::to_string), span));
                });
            }
            let site = |kind: &str, text: &str, span: Span, alias: &str| -> DependencyUsageSite {
                let (path, line, column) = crate::analysis::resolve_span_location(ws, span);
                let enclosing = enclosing_index.enclosing(span.start);
                DependencyUsageSite {
                    file: bonsai_common::workspace_relative_filter_path(root.as_deref(), &path),
                    line,
                    column,
                    kind: kind.to_string(),
                    text: text.to_string(),
                    in_function: enclosing.as_ref().map(|entry| entry.name.clone()),
                    via_alias: Some(alias.to_string()),
                    rule_id: None,
                    in_func: enclosing.map(|entry| FuncId::new(entry.symbol.raw())),
                }
            };
            for (row_index, file_names) in file_names_by_row {
                for (name, receiver, span) in &calls {
                    if let Some(alias) = bound_name_for(name, receiver.as_deref(), &file_names) {
                        out.sites.push((row_index, site("call", name, *span, alias)));
                    }
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
                        out.sites
                            .push((row_index, site(kind, &reference.name, reference.span, alias)));
                    }
                }
                out.bound_names.push((row_index, file_names));
            }
            Some(out)
        })
        .collect();
    // Ordered merge keeps the output identical to the sequential walk.
    for usage in per_file.into_iter().flatten() {
        if let Some(reason) = usage.incomplete {
            incomplete_reasons.push(reason);
        }
        for (row_index, site) in usage.sites {
            usages[row_index].sites.push(site);
        }
        for (row_index, names) in usage.bound_names {
            usages[row_index].bound_names.extend(names);
        }
    }
    usages
}

fn bound_name_for<'a>(callee: &str, receiver: Option<&str>, names: &'a [String]) -> Option<&'a str> {
    // The head of `name.member` / `name::member` / `name->member` /
    // `name:member`, computed once without allocating.
    let head = qualified_head(callee);
    names
        .iter()
        .map(String::as_str)
        .find(|name| callee == *name || receiver == Some(*name) || head.is_some_and(|head| head == *name))
}

/// `callee` up to its first member separator, or `None` when it has none.
fn qualified_head(callee: &str) -> Option<&str> {
    let bytes = callee.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'.' | b':' => return (index > 0).then(|| &callee[..index]),
            b'-' if bytes.get(index + 1) == Some(&b'>') => return (index > 0).then(|| &callee[..index]),
            _ => index += 1,
        }
    }
    None
}

fn module_tail(module: &str) -> Option<&str> {
    module
        .rsplit(['.', '/', ':', '\\'])
        .next()
        .filter(|tail| !tail.is_empty())
}

/// Visit every call event (including calls nested in branches, loops,
/// try/catch, defer/using bodies, and assignment sources).
/// Visit every call site in a flow-event tree. An assignment whose value is
/// a call (`x = pkg.f()`) is reported at the call expression, not at the
/// assignment: one pre-order pass records every `Call` span by callee name,
/// and an assign is emitted only when no recorded call of that name sits
/// inside its span.
fn walk_calls(events: &[FlowEvent], visit: &mut dyn FnMut(&str, Option<&str>, Span)) {
    let mut call_spans_by_name: ahash::AHashMap<&str, Vec<Span>> = ahash::AHashMap::new();
    let mut pending_assigns: Vec<(&str, Span)> = Vec::new();
    for_each_nested(events, &mut |event| match event {
        FlowEvent::Call {
            name, receiver, span, ..
        } => {
            call_spans_by_name.entry(name.as_str()).or_default().push(*span);
            visit(name, receiver.as_deref(), *span);
        }
        FlowEvent::Assign {
            span, source_call, ..
        } => {
            if let Some(name) = source_call.as_deref() {
                pending_assigns.push((name, *span));
            }
        }
        _ => {}
    });
    for (name, span) in pending_assigns {
        let already_recorded = call_spans_by_name.get(name).is_some_and(|spans| {
            spans
                .iter()
                .any(|call| call.file == span.file && call.start >= span.start && call.end <= span.end)
        });
        if !already_recorded {
            visit(name, None, span);
        }
    }
}

/// Pre-order walk over a flow-event tree and every nested block.
fn for_each_nested<'a>(events: &'a [FlowEvent], visit: &mut dyn FnMut(&'a FlowEvent)) {
    for event in events {
        visit(event);
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                for_each_nested(then_events, visit);
                for_each_nested(else_events, visit);
            }
            FlowEvent::Loop {
                condition_events,
                update_events,
                body,
                ..
            } => {
                for_each_nested(condition_events, visit);
                for_each_nested(update_events, visit);
                for_each_nested(body, visit);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                for_each_nested(body, visit);
                for_each_nested(catch_events, visit);
                for_each_nested(finally_events, visit);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => for_each_nested(body, visit),
            _ => {}
        }
    }
}

fn enclosing_func_at(ws: &Workspace, span: Span) -> Option<FuncId> {
    let headers = ws.compiler_header_index();
    ws.enclosing_index()
        .enclosing_for(headers.as_ref(), span.file, span.start)
        .map(|entry| FuncId::new(entry.symbol.raw()))
}

fn file_display_path(ws: &Workspace, file: FileId) -> String {
    ws.vfs()
        .path(file)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| format!("file#{}", file.raw()))
}
