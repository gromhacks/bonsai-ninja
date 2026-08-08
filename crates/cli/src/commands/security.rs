//! `bonsai-ninja security` command family. The CLI surface mirrors
//! `bonsai-ninja search` — every subcommand is a pre-canned, paginated
//! query whose "query string" is the loaded rulepack. There is no
//! discovery mode; the rulepack IS the query, and the YAML rules are
//! the source of truth for what counts as a source / sink / dep.
//!
//! - `sources` / `sinks` / `deps` render search-style tables with the
//!   standard paging / `--context` / `--page` flags.
//! - `taint-analysis` runs automatic source→sink taint and emits an
//!   inspect-style finding report, paginated one finding per block.
//! - `source-analysis` renders downstream source-driven paths without
//!   requiring a sink rule, for entrypoint / attack-surface mapping.

mod progress_ui;

use self::progress_ui::{ScopedProgress, SecurityAnalysisProgress};
use crate::args::{BrowseFormat, SecurityAction, SecurityFormat};
use crate::commands::{
    emit_json_paged_cached, emit_json_value_paged_cached, open_project_index_filtered_paths,
    open_project_index_matching_literal, open_project_index_only, page_info_to_json,
    paged_json_incomplete_reasons, paging_from_cli, paging_with_row_limit, short_file,
};
use crate::footer::{render_paging_footer, render_truncation_notice};
use crate::page_cache;
use crate::paging;
use crate::ui::{extension_for, Ui};
use crate::{cli_print, cli_println, progress, ui};
use anyhow::{bail, Context, Result};
use bonsai_common::{FuncId, Precision, Span};
use bonsai_sdk::{
    load_rulepack, load_workspace_local_rules, parse_severity, security_match_rows, tree_file_rel,
    CombinedFindingWithChain, CombinedSourceAnalysisCandidate, DependencyInventoryOptions, DependencyRow,
    Finding, FindingMatch, FindingStatus, PackAuditReport, PackInventoryOptions, PackRuleRow, Rule, RuleKind,
    RuleMatch, Rulepack, RulepackMetadata, RuntimeDisabledRule, SecurityInventoryOptions, SecurityMatchRow,
    SecurityReport, Severity, SourceAnalysisOptions, SourceLineageStatus, SourceLineageSummary,
    TaintAnalysisOptions, TaintAnalysisReport, TaintPropagationArg, TaintPropagationStep, TrustClass,
};
use comfy_table::Cell;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn source_analysis_json_incomplete_reasons(
    command: &str,
    info: &paging::PageInfo,
    rows: &[CombinedSourceAnalysisFlow],
    report_reasons: &[String],
) -> Vec<String> {
    let mut reasons = report_reasons.to_vec();
    reasons.extend(paged_json_incomplete_reasons(command, info));
    for row in rows {
        if row.analysis_complete {
            continue;
        }
        if row.analysis_incomplete_reasons.is_empty() {
            reasons.push("source-analysis row incomplete: unknown reason".to_string());
        } else {
            reasons.extend(
                row.analysis_incomplete_reasons
                    .iter()
                    .map(|reason| format!("source-analysis row incomplete: {reason}")),
            );
        }
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

const TAINT_RENDER_CACHE_KIND: &str = "security/taint-analysis/render-report/v10";

#[derive(Clone, Serialize, Deserialize)]
struct TaintAnalysisRenderReport {
    summary: TaintAnalysisSummary,
    findings: Vec<TaintAnalysisRenderFinding>,
    #[serde(default)]
    analysis_complete: bool,
    #[serde(default)]
    analysis_incomplete_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    runtime_disabled_rules: Vec<RuntimeDisabledRule>,
    /// True when every finding was saved after bulk flow-evidence
    /// attachment. JSON `--all` needs this because it serializes full
    /// finding rows; text output can rebuild flow bodies lazily.
    bulk_flow_evidence: bool,
    /// Render-only baseline summary. A baseline shapes output and must never
    /// enter the reusable semantic analysis payload.
    #[serde(skip)]
    baseline: Option<BaselineDiff>,
}

/// One finding in the cached render report. Flow render structs are
/// NOT stored here: a flow is derived purely from the finding's own
/// `hops` (see [`flow_from_finding_hops`]), and materializing one per
/// finding duplicates every hop body for the whole report at once —
/// on a large corpus that is gigabytes held just to show one page.
/// Flows are built lazily, only for the findings on a rendered page.
#[derive(Clone, Serialize, Deserialize)]
struct TaintAnalysisRenderFinding {
    #[serde(flatten)]
    finding: CombinedFindingWithChain,
    /// Raw FuncIds for the representative chain. This stays internal:
    /// public JSON rows should not expose process-local function ids.
    #[serde(skip)]
    chain_func_ids: Vec<u32>,
    /// `--baseline` diff status — `new` / `unchanged`. Set at render
    /// time only (never in the cached payload), so the cached analysis
    /// is reused across baseline-vs-no-baseline runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    baseline_status: Option<String>,
}

/// Result of classifying the current findings against a `--baseline`
/// file: how many are new vs unchanged, and which baseline findings are
/// gone now (fixed).
#[derive(Clone, Serialize)]
struct BaselineDiff {
    new: usize,
    fixed: usize,
    unchanged: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fixed_finding_ids: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct TaintAnalysisRenderReportCache {
    summary: TaintAnalysisSummary,
    findings: Vec<TaintAnalysisRenderFindingCache>,
    #[serde(default)]
    analysis_complete: bool,
    #[serde(default)]
    analysis_incomplete_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    runtime_disabled_rules: Vec<RuntimeDisabledRule>,
    #[serde(default)]
    bulk_flow_evidence: bool,
}

#[derive(Serialize, Deserialize)]
struct TaintAnalysisRenderFindingCache {
    #[serde(flatten)]
    finding: CombinedFindingWithChain,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    chain_func_ids: Vec<u32>,
}

impl From<&TaintAnalysisRenderReport> for TaintAnalysisRenderReportCache {
    fn from(report: &TaintAnalysisRenderReport) -> Self {
        Self {
            summary: report.summary.clone(),
            findings: report
                .findings
                .iter()
                .map(|item| TaintAnalysisRenderFindingCache {
                    finding: item.finding.clone(),
                    chain_func_ids: item.chain_func_ids.clone(),
                })
                .collect(),
            analysis_complete: report.analysis_complete,
            analysis_incomplete_reasons: report.analysis_incomplete_reasons.clone(),
            runtime_disabled_rules: report.runtime_disabled_rules.clone(),
            bulk_flow_evidence: report.bulk_flow_evidence,
        }
    }
}

impl From<TaintAnalysisRenderReportCache> for TaintAnalysisRenderReport {
    fn from(report: TaintAnalysisRenderReportCache) -> Self {
        Self {
            summary: report.summary,
            findings: report
                .findings
                .into_iter()
                .map(|item| TaintAnalysisRenderFinding {
                    finding: item.finding,
                    chain_func_ids: item.chain_func_ids,
                    baseline_status: None,
                })
                .collect(),
            analysis_complete: report.analysis_complete,
            analysis_incomplete_reasons: report.analysis_incomplete_reasons,
            runtime_disabled_rules: report.runtime_disabled_rules,
            bulk_flow_evidence: report.bulk_flow_evidence,
            baseline: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct TaintAnalysisSummary {
    #[serde(default)]
    analysis_complete: bool,
    #[serde(default)]
    analysis_incomplete_reasons: Vec<String>,
    total_findings: usize,
    source_rule_count: usize,
    sink_rule_count: usize,
    sanitizer_rule_count: usize,
    severity_counts: BTreeMap<String, usize>,
    status_counts: BTreeMap<String, usize>,
    precision_counts: BTreeMap<String, usize>,
    tag_counts: BTreeMap<String, usize>,
    language_counts: BTreeMap<String, usize>,
    source_rule_counts: BTreeMap<String, usize>,
    sink_rule_counts: BTreeMap<String, usize>,
    source_trust_counts: BTreeMap<String, usize>,
    source_category_counts: BTreeMap<String, usize>,
    sink_file_counts: BTreeMap<String, usize>,
}

/// Open the workspace and attach the already-loaded rulepack so every
/// security subcommand sees the same rules without reloading.
///
/// Security commands open with structural facts and valid sidecars
/// loaded, but without eager whole-workspace taint/value-flow
/// prewarm. The exact analysis phase owns its requested scope
/// (`--file`, `--source`, profile filters, sinks, export mode, etc.)
/// and computes that scope before rendering; opening the workspace
/// must not silently perform a broader full-workspace solve.
fn open_security_project(
    workspace: &Path,
    pack: &Rulepack,
    rules_dir: &Path,
) -> Result<(bonsai_sdk::Project, crate::footer::WorkspaceFooter)> {
    let (project, footer) = open_project_index_only(workspace)?;
    Ok((project.with_loaded_rulepack(rules_dir, pack.clone()), footer))
}

fn open_security_project_matching_literal(
    workspace: &Path,
    pack: &Rulepack,
    rules_dir: &Path,
    literal: &str,
) -> Result<(bonsai_sdk::Project, crate::footer::WorkspaceFooter)> {
    let (project, footer) = open_project_index_matching_literal(workspace, literal)?;
    Ok((project.with_loaded_rulepack(rules_dir, pack.clone()), footer))
}

fn open_security_project_filtered_paths(
    workspace: &Path,
    pack: &Rulepack,
    rules_dir: &Path,
    include_filters: &[String],
    exclude_filters: &[String],
) -> Result<(bonsai_sdk::Project, crate::footer::WorkspaceFooter)> {
    let (project, footer) = open_project_index_filtered_paths(workspace, include_filters, exclude_filters)?;
    Ok((project.with_loaded_rulepack(rules_dir, pack.clone()), footer))
}

/// Top-level dispatcher for `bonsai-ninja security <action>`. Loads the
/// rulepack once, merges any project-local overrides, then forwards
/// to the per-action handler.
pub(crate) fn cmd_security(workspace: &Path, action: SecurityAction) -> Result<()> {
    let command_started = std::time::Instant::now();
    // Extract --rules-dir from whichever action variant carries it.
    // Same shape on every variant; clap-derive forces a per-variant
    // field (`global = true` would route the flag but wouldn't show
    // it in subcommand --help output, so we duplicate per variant
    // for discoverability).
    let action_rules_dir: Option<&Path> = match &action {
        SecurityAction::Sources { rules_dir, .. }
        | SecurityAction::Sinks { rules_dir, .. }
        | SecurityAction::Sanitizers { rules_dir, .. }
        | SecurityAction::Deps { rules_dir, .. }
        | SecurityAction::TaintAnalysis { rules_dir, .. }
        | SecurityAction::SourceAnalysis { rules_dir, .. }
        | SecurityAction::Pack { rules_dir, .. } => rules_dir.as_deref(),
    };
    let rules_dir = resolve_rules_dir(workspace, action_rules_dir);
    let stage = progress::ScopedSpinner::new("loading security rules");
    let mut pack = load_rulepack(&rules_dir)
        .map_err(|e| anyhow::anyhow!("security: rulepack load failed at `{}`: {e}", rules_dir.display()))?;
    let mut project_local_overrides = Vec::new();
    if let Some(local) = load_workspace_local_rules(workspace)
        .map_err(|e| anyhow::anyhow!("security: project-local rule load failed: {e}"))?
    {
        project_local_overrides = pack.merge_overriding(local);
    }
    stage.finish();
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "security rulepack/setup: {:.3}s",
        command_started.elapsed().as_secs_f64()
    );
    if !project_local_overrides.is_empty() {
        let u = ui();
        for id in project_local_overrides {
            eprintln!(
                "{}",
                u.warn(&format!(
                    "warning: project-local rule `{id}` overrides global rule with the same id"
                ))
            );
        }
    }

    match action {
        SecurityAction::Sources {
            rules_dir: _,
            rule,
            rule_regex,
            trust,
            category,
            tag,
            files,
            exclude_files,
            limit,
            context,
            page,
            all,
            format,
            output: _,
        } => {
            let paging_cfg = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_sources(
                workspace,
                &pack,
                &rules_dir,
                rule,
                rule_regex,
                trust,
                category,
                tag,
                files,
                exclude_files,
                limit,
                paging_cfg,
                format,
            )
        }
        SecurityAction::Sinks {
            rules_dir: _,
            rule,
            rule_regex,
            severity,
            tag,
            category,
            files,
            exclude_files,
            limit,
            context,
            page,
            all,
            format,
            output: _,
        } => {
            let paging_cfg = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_sinks(
                workspace,
                &pack,
                &rules_dir,
                rule,
                rule_regex,
                severity,
                tag,
                category,
                files,
                exclude_files,
                limit,
                paging_cfg,
                format,
            )
        }
        SecurityAction::Sanitizers {
            rules_dir: _,
            rule,
            rule_regex,
            tag,
            severity,
            category,
            files,
            exclude_files,
            limit,
            context,
            page,
            all,
            format,
            output: _,
        } => {
            let paging_cfg = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_sanitizers(
                workspace,
                &pack,
                &rules_dir,
                rule,
                rule_regex,
                tag,
                severity,
                category,
                files,
                exclude_files,
                limit,
                paging_cfg,
                format,
            )
        }
        SecurityAction::Deps {
            rules_dir: _,
            framework,
            severity,
            files,
            exclude_files,
            limit,
            context,
            page,
            all,
            format,
            output: _,
        } => {
            let paging_cfg = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_deps(
                workspace,
                &pack,
                &rules_dir,
                framework,
                severity,
                files,
                exclude_files,
                limit,
                paging_cfg,
                format,
            )
        }
        SecurityAction::TaintAnalysis {
            rules_dir: _,
            profile,
            source,
            finding,
            flow,
            group,
            mut trust,
            category,
            sink,
            mut severity,
            tag,
            files,
            mut exclude_files,
            inferred_sources,
            include_pattern_only,
            mut exclude_tests,
            show_sanitized,
            mut context,
            page,
            all,
            summary,
            format,
            baseline,
            explain,
            output: _,
        } => {
            apply_profile(
                &pack.metadata,
                profile.as_deref(),
                ProfileOverrides {
                    trust: &mut trust,
                    severity: Some(&mut severity),
                    exclude_files: &mut exclude_files,
                    exclude_tests: Some(&mut exclude_tests),
                    context: &mut context,
                },
            )?;
            let paging_cfg =
                paging_from_cli(context.as_deref(), page.as_deref(), all, format.paging_format())?;
            cmd_flows(
                workspace,
                &pack,
                &rules_dir,
                source,
                finding,
                flow,
                group,
                trust,
                category,
                sink,
                severity,
                tag,
                files,
                exclude_files,
                inferred_sources,
                include_pattern_only,
                exclude_tests,
                show_sanitized,
                paging_cfg,
                summary,
                format,
                baseline.as_deref(),
                explain,
            )
        }
        SecurityAction::SourceAnalysis {
            rules_dir: _,
            profile,
            source,
            mut trust,
            tag,
            category,
            files,
            mut exclude_files,
            inferred_sources,
            mut context,
            page,
            all,
            format,
            output: _,
        } => {
            let mut exclude_tests = false;
            apply_profile(
                &pack.metadata,
                profile.as_deref(),
                ProfileOverrides {
                    trust: &mut trust,
                    severity: None,
                    exclude_files: &mut exclude_files,
                    exclude_tests: Some(&mut exclude_tests),
                    context: &mut context,
                },
            )?;
            let paging_cfg = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_source_analysis(
                workspace,
                &pack,
                &rules_dir,
                source,
                trust,
                tag,
                category,
                files,
                exclude_files,
                exclude_tests,
                inferred_sources,
                paging_cfg,
                format,
            )
        }
        SecurityAction::Pack {
            rules_dir: _,
            lang,
            category,
            kind,
            severity,
            audit,
            tree,
            validate,
            taint_replay,
            context,
            page,
            all,
            limit,
            format,
            output: _,
        } => {
            let paging_cfg = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_pack(
                workspace,
                &pack,
                lang,
                category,
                kind,
                severity,
                audit,
                tree,
                validate,
                taint_replay,
                limit,
                paging_cfg,
                format,
            )
        }
    }
}

/// Apply a rulepack-declared profile to per-flag fields. Explicit CLI values
/// win; metadata supplies only missing defaults. This keeps deployment trust,
/// severity, context, and ecosystem path inventories out of CLI source.
struct ProfileOverrides<'a> {
    trust: &'a mut Option<String>,
    severity: Option<&'a mut Option<String>>,
    exclude_files: &'a mut Vec<String>,
    exclude_tests: Option<&'a mut bool>,
    context: &'a mut Option<String>,
}

fn apply_profile(
    metadata: &RulepackMetadata,
    profile: Option<&str>,
    overrides: ProfileOverrides<'_>,
) -> Result<()> {
    let Some(name) = profile else {
        return Ok(());
    };
    let Some(profile) = metadata.profiles.get(name) else {
        let mut supported = metadata.profiles.keys().map(String::as_str).collect::<Vec<_>>();
        supported.sort_unstable();
        return Err(anyhow::anyhow!(
            "security: unknown --profile `{name}`; supported: {}",
            supported.join(", ")
        ));
    };
    if overrides.trust.is_none() {
        *overrides.trust = profile.trust.map(|value| value.as_str().to_string());
    }
    if let Some(severity) = overrides.severity {
        if severity.is_none() {
            *severity = profile.severity.map(|value| value.as_str().to_string());
        }
    }
    if overrides.exclude_files.is_empty() {
        overrides.exclude_files.clone_from(&profile.exclude_paths);
    }
    if profile.exclude_tests == Some(true) {
        if let Some(exclude_tests) = overrides.exclude_tests {
            *exclude_tests = true;
        }
    }
    if overrides.context.is_none() {
        overrides.context.clone_from(&profile.context);
    }
    Ok(())
}

/// Resolve the rulepack directory: explicit `--rules-dir` wins; otherwise
/// fall back to the SDK's centralised workspace/package discovery, then the
/// conventional cwd-relative `security-patterns/` path for a useful error.
fn resolve_rules_dir(workspace: &Path, rules_dir: Option<&Path>) -> PathBuf {
    if let Some(d) = rules_dir {
        return d.to_path_buf();
    }
    bonsai_sdk::Bonsai::discover_rulepack_root(workspace)
        .unwrap_or_else(|| PathBuf::from("security-patterns"))
}

// ---- sources ----
#[allow(clippy::too_many_arguments)] // Mirrors CLI filters; grouping would obscure the dispatcher mapping.
fn cmd_sources(
    workspace: &Path,
    pack: &Rulepack,
    rules_dir: &Path,
    rule: Option<String>,
    rule_regex: Option<String>,
    trust: Option<String>,
    category: Option<String>,
    tag: Option<String>,
    files: Vec<String>,
    exclude_files: Vec<String>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let literal_anchor = source_inventory_exact_rule_literal(
        pack,
        rule.as_deref(),
        rule_regex.as_deref(),
        trust.as_deref(),
        category.as_deref(),
        tag.as_deref(),
    );
    let (project, _footer) = if let Some(literal) = literal_anchor.as_deref() {
        open_security_project_matching_literal(workspace, pack, rules_dir, literal)?
    } else {
        open_security_project(workspace, pack, rules_dir)?
    };
    let options = SecurityInventoryOptions {
        rule: rule.clone(),
        rule_regex: rule_regex.clone(),
        trust: trust.clone(),
        category: category.clone(),
        tag: tag.clone(),
        files: files.clone(),
        exclude_files: exclude_files.clone(),
        ..Default::default()
    };
    let mut analysis_progress = SecurityAnalysisProgress::new();
    let matches = project
        .security()
        .sources_with_progress(options, |event| analysis_progress.handle(event))?;
    render_match_table(
        workspace,
        "sources",
        &matches,
        pack,
        project.workspace(),
        limit,
        paging_cfg,
        format,
        false,
        filter_signature(&[
            ("kind", "source"),
            ("rule", rule.as_deref().unwrap_or("")),
            ("rule_regex", rule_regex.as_deref().unwrap_or("")),
            ("trust", trust.as_deref().unwrap_or("")),
            ("category", category.as_deref().unwrap_or("")),
            ("tag", tag.as_deref().unwrap_or("")),
        ]),
    )
}

fn source_inventory_exact_rule_literal(
    pack: &Rulepack,
    rule: Option<&str>,
    rule_regex: Option<&str>,
    trust: Option<&str>,
    category: Option<&str>,
    tag: Option<&str>,
) -> Option<String> {
    if rule_regex.is_some() {
        return None;
    }
    let exact = rule?;
    let mut selected = pack.all_rules().into_iter().filter(|candidate| {
        candidate.kind == RuleKind::Source
            && candidate.enabled
            && (candidate.id == exact || candidate.aliases.iter().any(|alias| alias == exact))
            && trust.is_none_or(|wanted| candidate.trust.is_some_and(|actual| actual.as_str() == wanted))
            && category.is_none_or(|wanted| candidate.category.as_deref() == Some(wanted))
            && tag.is_none_or(|wanted| candidate.tag.as_deref() == Some(wanted))
    });
    let source_rule = selected.next()?;
    if selected.next().is_some() {
        return None;
    }
    literal_anchor_for_rule_target(source_rule)
}

fn literal_anchor_for_rule_target(rule: &Rule) -> Option<String> {
    for signal in rule
        .packages
        .iter()
        .chain(rule.imports.iter())
        .chain(rule.modules.iter())
    {
        if safe_inventory_literal_anchor(signal) {
            return Some(signal.clone());
        }
    }
    let target = rule
        .match_spec
        .target
        .as_ref()
        .or(rule.match_spec.callee.as_ref())?;
    if let Some(annotation) = target.annotation.as_deref() {
        if safe_inventory_literal_anchor(annotation) {
            return Some(annotation.to_string());
        }
    }
    if let Some(name) = target.name.as_deref() {
        if safe_inventory_literal_anchor(name) {
            return Some(name.to_string());
        }
    }
    if let Some(attribute) = target.attribute.as_ref() {
        // The terminal callable/property is the narrowest source-text anchor
        // that remains valid across imports and aliases. Never special-case a
        // provider namespace here; exact matching still happens on compiler
        // facts after candidate retrieval.
        for part in attribute.iter().rev() {
            if safe_inventory_literal_anchor(part) {
                return Some(part.clone());
            }
        }
    }
    None
}

fn safe_inventory_literal_anchor(literal: &str) -> bool {
    let literal = literal.trim();
    literal.len() >= 3
        && literal.bytes().all(|byte| {
            byte == b'_'
                || byte == b'$'
                || byte == b'@'
                || byte == b'.'
                || byte == b'/'
                || byte == b':'
                || byte == b'-'
                || byte.is_ascii_alphanumeric()
        })
}

// ---- sinks ----
#[allow(clippy::too_many_arguments)] // Mirrors CLI filters; grouping would obscure the dispatcher mapping.
fn cmd_sinks(
    workspace: &Path,
    pack: &Rulepack,
    rules_dir: &Path,
    rule: Option<String>,
    rule_regex: Option<String>,
    severity: Option<String>,
    tag: Option<String>,
    category: Option<String>,
    files: Vec<String>,
    exclude_files: Vec<String>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let command_started = std::time::Instant::now();
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let (project, _footer) = if !files.is_empty() || !exclude_files.is_empty() {
        open_security_project_filtered_paths(workspace, pack, rules_dir, &files, &exclude_files)?
    } else {
        open_security_project(workspace, pack, rules_dir)?
    };
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "sink inventory workspace open: {:.3}s",
        command_started.elapsed().as_secs_f64()
    );
    let sev_floor = parse_severity_flag(severity.as_deref())?;
    let mut analysis_progress = SecurityAnalysisProgress::new();
    let matches = project.security().sinks_with_progress(
        SecurityInventoryOptions {
            rule: rule.clone(),
            rule_regex: rule_regex.clone(),
            severity: sev_floor,
            tag: tag.clone(),
            category: category.clone(),
            files: files.clone(),
            exclude_files: exclude_files.clone(),
            ..Default::default()
        },
        |event| analysis_progress.handle(event),
    )?;
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "sink inventory analysis complete: {:.3}s matches={}",
        command_started.elapsed().as_secs_f64(),
        matches.len()
    );
    let result = render_match_table(
        workspace,
        "sinks",
        &matches,
        pack,
        project.workspace(),
        limit,
        paging_cfg,
        format,
        true,
        filter_signature(&[
            ("kind", "sink"),
            ("rule", rule.as_deref().unwrap_or("")),
            ("rule_regex", rule_regex.as_deref().unwrap_or("")),
            ("severity", severity.as_deref().unwrap_or("")),
            ("tag", tag.as_deref().unwrap_or("")),
            ("category", category.as_deref().unwrap_or("")),
        ]),
    );
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "sink inventory command complete: {:.3}s",
        command_started.elapsed().as_secs_f64()
    );
    result
}

// ---- sanitizers ----
#[allow(clippy::too_many_arguments)] // Mirrors CLI filters; grouping would obscure the dispatcher mapping.
fn cmd_sanitizers(
    workspace: &Path,
    pack: &Rulepack,
    rules_dir: &Path,
    rule: Option<String>,
    rule_regex: Option<String>,
    tag: Option<String>,
    severity: Option<String>,
    category: Option<String>,
    files: Vec<String>,
    exclude_files: Vec<String>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let (project, _footer) = if !files.is_empty() || !exclude_files.is_empty() {
        open_security_project_filtered_paths(workspace, pack, rules_dir, &files, &exclude_files)?
    } else {
        open_security_project(workspace, pack, rules_dir)?
    };
    let sev_floor = parse_severity_flag(severity.as_deref())?;
    let mut analysis_progress = SecurityAnalysisProgress::new();
    let matches = project.security().sanitizers_with_progress(
        SecurityInventoryOptions {
            rule: rule.clone(),
            rule_regex: rule_regex.clone(),
            tag: tag.clone(),
            severity: sev_floor,
            category: category.clone(),
            files: files.clone(),
            exclude_files: exclude_files.clone(),
            ..Default::default()
        },
        |event| analysis_progress.handle(event),
    )?;
    render_match_table(
        workspace,
        "sanitizers",
        &matches,
        pack,
        project.workspace(),
        limit,
        paging_cfg,
        format,
        false,
        filter_signature(&[
            ("kind", "sanitizer"),
            ("rule", rule.as_deref().unwrap_or("")),
            ("rule_regex", rule_regex.as_deref().unwrap_or("")),
            ("tag", tag.as_deref().unwrap_or("")),
            ("severity", severity.as_deref().unwrap_or("")),
            ("category", category.as_deref().unwrap_or("")),
        ]),
    )
}

// ---- deps ----
#[allow(clippy::too_many_arguments)] // Mirrors CLI filters; grouping would obscure the dispatcher mapping.
fn cmd_deps(
    workspace: &Path,
    pack: &Rulepack,
    rules_dir: &Path,
    framework: Option<String>,
    severity: Option<String>,
    files: Vec<String>,
    exclude_files: Vec<String>,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let (project, _footer) = if !files.is_empty() || !exclude_files.is_empty() {
        open_security_project_filtered_paths(workspace, pack, rules_dir, &files, &exclude_files)?
    } else {
        open_security_project(workspace, pack, rules_dir)?
    };
    let collect_progress = ScopedProgress::new("collecting dependency inventory");
    let inv = project.security().deps(DependencyInventoryOptions {
        framework: framework.clone(),
        severity: parse_severity_flag(severity.as_deref())?,
        files: files.clone(),
        exclude_files: exclude_files.clone(),
    })?;
    collect_progress.finish();

    let filters_hash = filter_signature(&[
        ("kind", "deps"),
        ("framework", framework.as_deref().unwrap_or("")),
        ("severity", severity.as_deref().unwrap_or("")),
    ]);
    let cost = |r: &DependencyRow| dep_block_cost_bytes(r, pack);

    match format {
        BrowseFormat::Json => {
            emit_json_paged_cached(
                workspace,
                &inv.rows,
                &paging_cfg,
                "security/deps",
                filters_hash,
                cost,
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                workspace,
                &inv.rows,
                &paging_cfg,
                "security/deps",
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let limit_eff = effective_limit(limit, cfg);
                    let truncated = if limit_eff != 0 && paged.len() > limit_eff {
                        Some(paged.len() - limit_eff)
                    } else {
                        None
                    };
                    let rows: Vec<DependencyRow> = if limit_eff == 0 {
                        paged.to_vec()
                    } else {
                        paged.iter().take(limit_eff).cloned().collect()
                    };
                    let u = ui();
                    cli_println!(
                        "{}",
                        u.dim(&format!("security deps — {} package(s)", inv.rows.len()))
                    );
                    for (idx, r) in rows.iter().enumerate() {
                        render_dep_block(u, idx + 1, r, pack);
                    }
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja security <workspace> deps");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

// ---- taint-analysis — automatic source→sink taint, inspect-style report ----
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)] // stable parameter list — see calling site for shape
fn cmd_flows(
    workspace: &Path,
    pack: &Rulepack,
    rules_dir: &Path,
    source: Option<String>,
    finding: Option<String>,
    flow: Option<String>,
    group: Option<String>,
    trust: Option<String>,
    category: Option<String>,
    sink: Option<String>,
    severity: Option<String>,
    tag: Option<String>,
    files: Vec<String>,
    exclude_files: Vec<String>,
    inferred_sources: bool,
    include_pattern_only: bool,
    exclude_tests: bool,
    show_sanitized: bool,
    paging_cfg: paging::PagingConfig,
    summary_only: bool,
    format: SecurityFormat,
    baseline: Option<&Path>,
    explain: bool,
) -> Result<()> {
    let sev_floor = parse_severity_flag(severity.as_deref())?;
    let max_precision = Some(Precision::Narrowed);
    if summary_only && matches!(format, SecurityFormat::Sarif) {
        bail!("`security taint-analysis --summary` supports text or json output, not sarif");
    }
    if baseline.is_some() && matches!(format, SecurityFormat::Sarif) {
        bail!("`security taint-analysis --baseline` supports text or json output, not sarif");
    }
    if explain && matches!(format, SecurityFormat::Sarif) {
        bail!("`security taint-analysis --explain` supports text or json output, not sarif");
    }
    if finding.is_some() && explain {
        bail!("`security taint-analysis --finding` cannot be combined with --explain");
    }
    if group.is_some() && explain {
        bail!("`security taint-analysis --group` cannot be combined with --explain");
    }
    // Render-time diff input — does NOT enter the analysis cache key.
    let baseline_ids = baseline.map(load_baseline_finding_ids).transpose()?;
    let include_pattern_only = include_pattern_only || matches!(format, SecurityFormat::Sarif);
    // SEMANTIC analysis key: every input that changes the FINDING SET,
    // and nothing else. Output-shaping flags (format, paging, the
    // secondary `--contains` / `--not-contains` filters) are
    // deliberately excluded so the cached analysis is reused when only
    // the rendering changes. The `files`/`exclude_files`/
    // `inferred_sources`/`exclude_tests` inputs MUST be here — they
    // narrow the analysis, so omitting them would serve a stale result
    // when they change.
    let files_filter = files.join(",");
    let exclude_files_filter = exclude_files.join(",");
    let filters_hash = filter_signature(&[
        ("kind", "taint-analysis"),
        ("source", source.as_deref().unwrap_or("")),
        ("finding", finding.as_deref().unwrap_or("")),
        ("flow", flow.as_deref().unwrap_or("")),
        ("group", group.as_deref().unwrap_or("")),
        ("trust", trust.as_deref().unwrap_or("")),
        ("category", category.as_deref().unwrap_or("")),
        ("sink", sink.as_deref().unwrap_or("")),
        ("severity", severity.as_deref().unwrap_or("")),
        ("tag", tag.as_deref().unwrap_or("")),
        ("files", &files_filter),
        ("exclude_files", &exclude_files_filter),
        ("inferred_sources", if inferred_sources { "1" } else { "0" }),
        ("exclude_tests", if exclude_tests { "1" } else { "0" }),
        ("show_sanitized", if show_sanitized { "1" } else { "0" }),
        ("precision", "semantic"),
        (
            "include_pattern_only",
            if include_pattern_only { "1" } else { "0" },
        ),
    ]);

    // `--explain` needs the project (to count source/sink match sites),
    // so it bypasses the rendered-report fast path. SARIF is rendered
    // directly from the raw security report, and finding-specific
    // renders intentionally rerun the narrow request. Text `--all` can
    // reuse compact cached findings because it attaches flow bodies
    // lazily; JSON `--all` needs a payload saved with bulk flow
    // evidence.
    let needs_bulk_flow_evidence_cache =
        !summary_only && matches!(format, SecurityFormat::Json) && paging_cfg.all;
    if !explain
        && !matches!(format, SecurityFormat::Sarif)
        && finding.is_none()
        && flow.is_none()
        && group.is_none()
    {
        if let Some(cached_report) = page_cache::read_keyed_payload::<TaintAnalysisRenderReportCache>(
            workspace,
            filters_hash,
            TAINT_RENDER_CACHE_KIND,
        )? {
            let cached_report = TaintAnalysisRenderReport::from(cached_report);
            if !summary_only && cached_report.findings.is_empty() && cached_report.summary.total_findings > 0
            {
                tracing::debug!(
                    "ignoring taint render cache payload with summary count but no finding bodies"
                );
            } else if needs_bulk_flow_evidence_cache && !cached_report.bulk_flow_evidence {
                tracing::debug!(
                    "ignoring compact taint render cache payload for JSON --all bulk flow evidence"
                );
            } else {
                let cached_render_project = if matches!(format, SecurityFormat::Text) && !summary_only {
                    Some(if !files.is_empty() || !exclude_files.is_empty() {
                        open_security_project_filtered_paths(
                            workspace,
                            pack,
                            rules_dir,
                            &files,
                            &exclude_files,
                        )?
                    } else {
                        open_security_project(workspace, pack, rules_dir)?
                    })
                } else {
                    None
                };
                let render_workspace = cached_render_project
                    .as_ref()
                    .map(|(project, _footer)| project.workspace());
                let render_progress = ScopedProgress::new("rendering cached taint report");
                emit_taint_render_report(
                    workspace,
                    render_workspace,
                    pack,
                    &cached_report,
                    &paging_cfg,
                    summary_only,
                    format,
                    filters_hash,
                    None,
                    baseline_ids.as_ref(),
                )?;
                render_progress.finish();
                return Ok(());
            }
        }
    }

    let (project, _footer) = if !files.is_empty() || !exclude_files.is_empty() {
        open_security_project_filtered_paths(workspace, pack, rules_dir, &files, &exclude_files)?
    } else {
        open_security_project(workspace, pack, rules_dir)?
    };
    let mut analysis_progress = SecurityAnalysisProgress::new();
    let mut report = project.security().taint_analysis_with_phase_progress(
        TaintAnalysisOptions {
            source: source.clone(),
            flow_id: flow.clone(),
            trust: trust.clone(),
            category: category.clone(),
            sink: sink.clone(),
            severity: sev_floor,
            tag: tag.clone(),
            files: files.clone(),
            exclude_files: exclude_files.clone(),
            include_inferred_sources: inferred_sources,
            include_pattern_only,
            show_sanitized,
            max_precision,
            exclude_tests,
            attach_flow_evidence: false,
            taint_graph_resident_cache_entries: Some(0),
        },
        |event| analysis_progress.handle(event),
    )?;
    let runtime_disabled_rules = report.runtime_disabled_rules.clone();
    if let Some(finding_id) = finding.as_deref() {
        filter_report_to_finding_id(&mut report, finding_id)?;
    }
    if let Some(flow_id) = flow.as_deref() {
        ensure_report_has_security_flow_id(&report, flow_id)?;
    }
    if let Some(group_id) = group.as_deref() {
        filter_report_to_security_group_id(&mut report, group_id)?;
    }
    let bulk_flow_evidence_attached = !summary_only
        && (matches!(format, SecurityFormat::Sarif)
            || paging_cfg.all
            || finding.is_some()
            || flow.is_some()
            || group.is_some());
    if bulk_flow_evidence_attached {
        attach_flow_evidence_to_report(project.workspace(), &mut report);
    }

    if explain {
        return emit_taint_explain(
            &project,
            source.as_deref(),
            sink.as_deref(),
            trust.as_deref(),
            category.as_deref(),
            sev_floor,
            tag.as_deref(),
            &files,
            &exclude_files,
            &report,
            format,
        );
    }

    match format {
        SecurityFormat::Sarif => {
            let render_progress = ScopedProgress::new("rendering SARIF");
            // SARIF 2.1.0 — direct serialization, no pagination.
            // Standardised SAST output expected by IDE integrations,
            // GitHub code scanning, and the CVEBench-SAST harness.
            // SARIF consumers expect the full result set in one
            // document; --all behavior is implicit.
            let plain: Vec<Finding> = report.findings.iter().map(|f| f.finding.clone()).collect();
            // Drain runtime-disabled rules collected by the matcher
            // (invalid regex, etc.) so the SARIF report surfaces them
            // alongside findings. Without this, rules silently
            // dropped at runtime would never reach the user.
            let report = SecurityReport::with_runtime_disabled_rules(plain, runtime_disabled_rules)
                .with_analysis_completeness(report.analysis_complete, report.analysis_incomplete_reasons);
            let workspace_root = std::fs::canonicalize(workspace)
                .ok()
                .and_then(|path| path.to_str().map(str::to_owned))
                .unwrap_or_else(|| workspace.to_string_lossy().into_owned());
            cli_println!("{}", report.sarif_json_with_workspace_root(&workspace_root));
            render_progress.finish();
            return Ok(());
        }
        SecurityFormat::Json | SecurityFormat::Text => {}
    }

    let render_report = build_taint_render_report(
        report,
        /* include_findings = */ !summary_only || baseline_ids.is_some(),
        bulk_flow_evidence_attached,
    );
    let render_progress = ScopedProgress::new(if summary_only {
        "rendering taint summary"
    } else if matches!(format, SecurityFormat::Json) {
        "rendering taint JSON"
    } else {
        "rendering taint page"
    });
    emit_taint_render_report(
        workspace,
        if matches!(format, SecurityFormat::Text) && !summary_only {
            Some(project.workspace())
        } else {
            None
        },
        pack,
        &render_report,
        &paging_cfg,
        summary_only,
        format,
        filters_hash,
        Some(&render_report),
        baseline_ids.as_ref(),
    )?;
    render_progress.finish();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_taint_render_report(
    workspace: &Path,
    render_workspace: Option<&bonsai_sdk::Workspace>,
    pack: &Rulepack,
    report: &TaintAnalysisRenderReport,
    paging_cfg: &paging::PagingConfig,
    summary_only: bool,
    format: SecurityFormat,
    filters_hash: u64,
    cache_payload: Option<&TaintAnalysisRenderReport>,
    baseline_ids: Option<&std::collections::BTreeSet<String>>,
) -> Result<()> {
    // Both the secondary `--contains` filter and the `--baseline` diff
    // are RENDER-time: they shape what prints over an owned copy, while
    // `cache_payload` keeps pointing at the unfiltered, un-baselined
    // report — so the cached analysis is reused regardless of either.
    let secondary = crate::filter::active();
    let mut owned: Option<TaintAnalysisRenderReport> = None;
    if secondary.is_active() {
        owned = Some(filter_taint_render_report(report));
    }
    if let Some(ids) = baseline_ids {
        let target = owned.get_or_insert_with(|| report.clone());
        let diff = apply_baseline(target, ids);
        target.baseline = Some(diff);
    }
    let report: &TaintAnalysisRenderReport = owned.as_ref().unwrap_or(report);
    emit_taint_render_report_inner(
        workspace,
        render_workspace,
        pack,
        report,
        paging_cfg,
        summary_only,
        format,
        filters_hash,
        cache_payload,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_taint_render_report_inner(
    workspace: &Path,
    render_workspace: Option<&bonsai_sdk::Workspace>,
    pack: &Rulepack,
    report: &TaintAnalysisRenderReport,
    paging_cfg: &paging::PagingConfig,
    summary_only: bool,
    format: SecurityFormat,
    filters_hash: u64,
    cache_payload: Option<&TaintAnalysisRenderReport>,
) -> Result<()> {
    match format {
        SecurityFormat::Json if summary_only => {
            let mut summary = serde_json::to_value(&report.summary)?;
            if let (Some(diff), Some(fields)) = (report.baseline.as_ref(), summary.as_object_mut()) {
                fields.insert("baseline".to_string(), serde_json::to_value(diff)?);
            }
            cli_println!("{}", serde_json::to_string_pretty(&summary)?);
            save_taint_payload_if_requested(workspace, filters_hash, Vec::new(), None);
        }
        SecurityFormat::Text if summary_only => {
            let text = page_cache::capture(|| {
                render_taint_summary_text(&report.summary);
                if let Some(diff) = report.baseline.as_ref() {
                    render_baseline_summary_text(diff);
                }
                Ok(())
            })?;
            save_taint_payload_if_requested(workspace, filters_hash, Vec::new(), None);
            page_cache::emit_cached_text(&text)?;
        }
        SecurityFormat::Json => {
            let (pages, current_page) = build_taint_json_pages(report, paging_cfg, filters_hash)?;
            save_taint_payload_if_requested(workspace, filters_hash, pages.clone(), cache_payload);
            emit_cached_page(&pages, current_page)?;
        }
        SecurityFormat::Text => {
            let (pages, current_page) =
                build_taint_text_pages(render_workspace, pack, report, paging_cfg, filters_hash)?;
            save_taint_payload_if_requested(workspace, filters_hash, pages.clone(), cache_payload);
            emit_cached_page(&pages, current_page)?;
        }
        SecurityFormat::Sarif => {
            anyhow::bail!("internal format error: SARIF must be rendered before the cached taint report path")
        }
    }
    Ok(())
}

fn save_taint_payload_if_requested(
    workspace: &Path,
    filters_hash: u64,
    pages: Vec<page_cache::CachedPage>,
    payload: Option<&TaintAnalysisRenderReport>,
) {
    // Rendered pages key on the full argv (format / paging / secondary
    // filter) — they ARE the shaped output, so each variant caches its
    // own bytes for an identical re-run.
    if !pages.is_empty() {
        if let Err(e) = page_cache::save_pages(workspace, "security/taint-analysis", filters_hash, pages) {
            tracing::debug!("taint page cache save failed: {e}");
        }
    }
    // The full (unfiltered) analysis report keys on the SEMANTIC hash
    // only, so changing format / paging / `--contains` reuses it and
    // re-renders instead of re-analyzing.
    if let Some(payload) = payload {
        let cache_payload = TaintAnalysisRenderReportCache::from(payload);
        if !cache_payload.bulk_flow_evidence {
            if let Ok(Some(existing)) = page_cache::read_keyed_payload::<TaintAnalysisRenderReportCache>(
                workspace,
                filters_hash,
                TAINT_RENDER_CACHE_KIND,
            ) {
                if existing.bulk_flow_evidence {
                    return;
                }
            }
        }
        if let Err(e) =
            page_cache::save_keyed_payload(workspace, filters_hash, TAINT_RENDER_CACHE_KIND, &cache_payload)
        {
            tracing::debug!("taint report payload cache save failed: {e}");
        }
    }
}

fn emit_cached_page(pages: &[page_cache::CachedPage], current_page: u64) -> Result<()> {
    let Some(page) = pages.iter().find(|p| p.number == current_page) else {
        bail!("rendered taint page {current_page} missing from cache window");
    };
    page_cache::emit_cached_text(&page.text)?;
    Ok(())
}

fn filter_report_to_finding_id(report: &mut TaintAnalysisReport, finding_id: &str) -> Result<()> {
    report.findings.retain(|combined| {
        combined.finding.finding_id == finding_id
            || combined
                .member_finding_ids
                .iter()
                .any(|member_id| member_id == finding_id)
    });
    if report.findings.is_empty() {
        bail!(
            "no finding matching `{finding_id}` in this workspace + filter combination. \
             Finding ids are printed as `S:<hex>` in `security taint-analysis` text output \
             and as `finding.finding_id` in JSON output."
        );
    }
    Ok(())
}

fn ensure_report_has_security_flow_id(report: &TaintAnalysisReport, flow_id: &str) -> Result<()> {
    if report
        .findings
        .iter()
        .any(|combined| combined.finding.flow_ids().any(|candidate| candidate == flow_id))
    {
        return Ok(());
    }
    bail!(
        "no security flow matching `{flow_id}` in this workspace + filter combination. \
         Security flow ids are printed as `F:<hex>` in `security taint-analysis` text output \
         and as `representative_flow_id` in JSON output."
    );
}

fn filter_report_to_security_group_id(report: &mut TaintAnalysisReport, group_id: &str) -> Result<()> {
    report
        .findings
        .retain(|combined| combined.finding.group_id.as_deref() == Some(group_id));
    if report.findings.is_empty() {
        bail!(
            "no security flow group matching `{group_id}` in this workspace + filter combination. \
             Security group ids are printed as `G:<hex>` in `security taint-analysis` text output \
             and as `group_id` in JSON output."
        );
    }
    Ok(())
}

fn attach_flow_evidence_to_report(ws: &bonsai_sdk::Workspace, report: &mut TaintAnalysisReport) {
    for combined in &mut report.findings {
        if combined.finding.hops.is_empty() {
            combined.finding.hops = bonsai_sdk::build_flow_bodies(
                ws,
                &combined.chain_funcs,
                &combined.finding.source,
                &combined.finding.taint_path,
                bonsai_sdk::SecurityFlowRole::Sink,
            );
        }
    }
}

fn render_chain_funcs(item: &TaintAnalysisRenderFinding) -> Vec<FuncId> {
    if !item.finding.chain_funcs.is_empty() {
        return item.finding.chain_funcs.clone();
    }
    item.chain_func_ids.iter().copied().map(FuncId::new).collect()
}

fn attach_flow_evidence_to_render_finding(ws: &bonsai_sdk::Workspace, item: &mut TaintAnalysisRenderFinding) {
    if !item.finding.finding.hops.is_empty() {
        return;
    }
    let chain_funcs = render_chain_funcs(item);
    if chain_funcs.is_empty() {
        return;
    }
    item.finding.finding.hops = bonsai_sdk::build_flow_bodies(
        ws,
        &chain_funcs,
        &item.finding.finding.source,
        &item.finding.finding.taint_path,
        bonsai_sdk::SecurityFlowRole::Sink,
    );
}

fn build_taint_pages<C, R>(
    report: &TaintAnalysisRenderReport,
    paging_cfg: &paging::PagingConfig,
    filters_hash: u64,
    eager_pages: bool,
    cost_finding: C,
    mut render_page: R,
) -> Result<(Vec<page_cache::CachedPage>, u64)>
where
    C: Fn(&TaintAnalysisRenderFinding) -> u64,
    R: FnMut(&[usize], &paging::PageInfo, &paging::PagingConfig) -> Result<()>,
{
    let indexed: Vec<usize> = (0..report.findings.len()).collect();
    let cost = |finding_index: &usize| cost_finding(&report.findings[*finding_index]);
    let (_, current_info) = paging::paginate(
        &indexed,
        paging_cfg,
        "security/taint-analysis",
        filters_hash,
        cost,
    )?;
    let current_page = current_info.page_number;
    let mut pages = Vec::new();
    let page_numbers: Vec<u64> = if eager_pages {
        page_cache::eager_window(current_page, current_info.total_pages)
            .into_iter()
            .collect()
    } else {
        vec![current_page]
    };
    for page_number in page_numbers {
        let mut page_cfg = paging_cfg.clone();
        if page_number != current_page {
            page_cfg.page = paging::PageArg::Number(page_number);
        }
        let (paged_idx, info) =
            paging::paginate(&indexed, &page_cfg, "security/taint-analysis", filters_hash, cost)?;
        let text = page_cache::capture(|| render_page(&paged_idx, &info, &page_cfg))?;
        pages.push(page_cache::CachedPage {
            number: page_number,
            cursor: info.cursor,
            text,
        });
    }
    Ok((pages, current_page))
}

fn build_taint_json_pages(
    report: &TaintAnalysisRenderReport,
    paging_cfg: &paging::PagingConfig,
    filters_hash: u64,
) -> Result<(Vec<page_cache::CachedPage>, u64)> {
    build_taint_pages(
        report,
        paging_cfg,
        filters_hash,
        false,
        taint_json_cost_bytes,
        |paged_idx, info, page_cfg| render_taint_json_page(report, paged_idx, info, page_cfg),
    )
}

fn render_taint_json_page(
    report: &TaintAnalysisRenderReport,
    paged_idx: &[usize],
    info: &paging::PageInfo,
    _paging_cfg: &paging::PagingConfig,
) -> Result<()> {
    // Serialize the render-finding wrapper (the finding fields are
    // flattened in), so the `--baseline` `baseline_status` annotation
    // rides along on each row when present.
    let rows: Vec<&TaintAnalysisRenderFinding> = paged_idx.iter().map(|idx| &report.findings[*idx]).collect();
    // Security JSON is always an envelope, including `--all`. A bare empty
    // array cannot distinguish a proven clean scan from parser/resolution
    // failure, which is unsafe for automation.
    let mut analysis_incomplete_reasons = report.analysis_incomplete_reasons.clone();
    if !report.analysis_complete && analysis_incomplete_reasons.is_empty() {
        analysis_incomplete_reasons.push("taint-analysis incomplete: unknown reason".to_string());
    }
    analysis_incomplete_reasons.extend(paged_json_incomplete_reasons("security/taint-analysis", info));
    analysis_incomplete_reasons.sort();
    analysis_incomplete_reasons.dedup();
    let mut wrapped = serde_json::json!({
        "analysis_complete": report.analysis_complete && analysis_incomplete_reasons.is_empty(),
        "analysis_incomplete_reasons": analysis_incomplete_reasons,
        "runtime_disabled_rules": report.runtime_disabled_rules,
        "summary": compact_taint_summary(&report.summary),
        "rows": rows,
        "page": page_info_to_json(info),
    });
    if let (Some(diff), Some(fields)) = (report.baseline.as_ref(), wrapped.as_object_mut()) {
        fields.insert("baseline".to_string(), serde_json::to_value(diff)?);
    }
    cli_println!("{}", serde_json::to_string_pretty(&wrapped)?);
    Ok(())
}

fn build_taint_text_pages(
    render_workspace: Option<&bonsai_sdk::Workspace>,
    pack: &Rulepack,
    report: &TaintAnalysisRenderReport,
    paging_cfg: &paging::PagingConfig,
    filters_hash: u64,
) -> Result<(Vec<page_cache::CachedPage>, u64)> {
    let budget = paging_cfg.effective_budget();
    let unit_target_bytes = budget
        .map(|tokens| tokens.saturating_mul(paging::BYTES_PER_TOKEN).saturating_mul(25) / 100)
        .unwrap_or(u64::MAX / 8)
        .max(2_048);
    let page_payload_budget_bytes = budget
        .map(|tokens| tokens.saturating_mul(paging::BYTES_PER_TOKEN).saturating_mul(65) / 100)
        .unwrap_or(u64::MAX / 8)
        .max(unit_target_bytes);

    let units = build_taint_text_units(render_workspace, pack, report, unit_target_bytes)?;
    let page_bounds = taint_text_page_bounds(&units, page_payload_budget_bytes);
    let current_page = resolve_taint_text_page(&page_bounds, paging_cfg, filters_hash)?;
    let page_numbers: Vec<u64> = page_cache::eager_window(current_page, page_bounds.len() as u64)
        .into_iter()
        .collect();
    let mut pages = Vec::new();
    for page_number in page_numbers {
        let page_idx = usize::try_from(page_number.saturating_sub(1)).unwrap_or(usize::MAX);
        let Some(&(start, end)) = page_bounds.get(page_idx) else {
            continue;
        };
        let cursor = paging::cursor_id("security/taint-analysis", filters_hash, start as u64);
        let next_cursor = page_bounds.get(page_idx + 1).map(|(next_start, _)| {
            paging::cursor_id("security/taint-analysis", filters_hash, *next_start as u64)
        });
        let payload_bytes: u64 = units[start..end].iter().map(|unit| unit.text.len() as u64).sum();
        let info = paging::PageInfo {
            page_number,
            total_pages: page_bounds.len() as u64,
            page_size: (end - start) as u64,
            shown_rows: (end - start) as u64,
            total_rows: units.len() as u64,
            budget,
            tokens_used: paging::bytes_to_tokens(payload_bytes),
            cursor: cursor.clone(),
            next_cursor,
            is_last: page_idx + 1 >= page_bounds.len(),
            start_offset: start as u64,
            total_tokens_uncapped: units
                .iter()
                .map(|unit| paging::bytes_to_tokens(unit.text.len() as u64))
                .sum(),
        };
        let text = page_cache::capture(|| {
            render_taint_analysis_text_units(report, &units[start..end], &info)?;
            if let Some(diff) = report.baseline.as_ref() {
                render_baseline_summary_text(diff);
            }
            Ok(())
        })?;
        pages.push(page_cache::CachedPage {
            number: page_number,
            cursor,
            text,
        });
    }
    let current_idx = usize::try_from(current_page.saturating_sub(1)).unwrap_or(0);
    if let Some((start, _)) = page_bounds.get(current_idx) {
        let cursor = paging::cursor_id("security/taint-analysis", filters_hash, *start as u64);
        paging::write_last_cursor("security/taint-analysis", filters_hash, &cursor);
    }
    Ok((pages, current_page))
}

#[derive(Clone)]
struct TaintTextUnit {
    text: String,
}

fn build_taint_text_units(
    render_workspace: Option<&bonsai_sdk::Workspace>,
    pack: &Rulepack,
    report: &TaintAnalysisRenderReport,
    unit_target_bytes: u64,
) -> Result<Vec<TaintTextUnit>> {
    let mut units = Vec::new();
    for (finding_idx, original) in report.findings.iter().enumerate() {
        let mut item = original.clone();
        if let Some(ws) = render_workspace {
            attach_flow_evidence_to_render_finding(ws, &mut item);
        }
        match flow_from_finding_hops(&item.finding, finding_idx) {
            Some(flow) => {
                let chunks = split_security_flow_for_context(&flow, unit_target_bytes);
                let total_chunks = chunks.len().max(1);
                for (chunk_idx, chunk) in chunks.iter().enumerate() {
                    let text = page_cache::capture(|| {
                        render_taint_analysis_text_unit(
                            pack,
                            &item,
                            finding_idx,
                            Some(chunk),
                            chunk_idx,
                            total_chunks,
                        )
                    })?;
                    units.push(TaintTextUnit { text });
                }
            }
            None => {
                let text = page_cache::capture(|| {
                    render_taint_analysis_text_unit(pack, &item, finding_idx, None, 0, 1)
                })?;
                units.push(TaintTextUnit { text });
            }
        }
    }
    Ok(units)
}

fn render_taint_analysis_text_units(
    report: &TaintAnalysisRenderReport,
    units: &[TaintTextUnit],
    info: &paging::PageInfo,
) -> Result<()> {
    render_taint_analysis_report_heading(&report.summary);
    if report.analysis_complete {
        cli_println!("{}", ui().dim("analysis: complete"));
    } else {
        let u = ui();
        let reasons = if report.analysis_incomplete_reasons.is_empty() {
            "unknown semantic coverage gap".to_string()
        } else {
            report.analysis_incomplete_reasons.join(", ")
        };
        cli_println!("{}", u.warn(&format!("analysis incomplete — {reasons}")));
    }
    for disabled in &report.runtime_disabled_rules {
        cli_println!(
            "{}",
            ui().warn(&format!(
                "runtime-disabled rule {} — {}",
                disabled.rule_id, disabled.reason
            ))
        );
    }
    for unit in units {
        cli_print!("{}", unit.text);
    }
    render_paging_footer(info, "bonsai-ninja security <workspace> taint-analysis");
    Ok(())
}

fn render_taint_analysis_report_heading(summary: &TaintAnalysisSummary) {
    let u = ui();
    cli_println!(
        "{}",
        u.dim(&format!(
            "security taint-analysis — {} finding(s)  \
             (critical {}, high {}, medium {})  · \
             {} source rule(s) · {} sink rule(s) · {} sanitizer rule(s) loaded",
            summary.total_findings,
            summary.severity_counts.get("critical").copied().unwrap_or(0),
            summary.severity_counts.get("high").copied().unwrap_or(0),
            summary.severity_counts.get("medium").copied().unwrap_or(0),
            summary.source_rule_count,
            summary.sink_rule_count,
            summary.sanitizer_rule_count,
        ))
    );
}

fn render_taint_analysis_text_unit(
    pack: &Rulepack,
    item: &TaintAnalysisRenderFinding,
    finding_idx: usize,
    flow: Option<&crate::commands::InspectFlowRendered>,
    chunk_idx: usize,
    total_chunks: usize,
) -> Result<()> {
    let u = ui();
    if chunk_idx == 0 {
        render_finding_security_header(u, finding_idx + 1, &item.finding, pack);
        if item.baseline_status.as_deref() == Some("new") {
            cli_println!("  {}", u.warn("[NEW since baseline]"));
        }
    } else {
        render_finding_continuation_header(u, finding_idx + 1, &item.finding, chunk_idx + 1, total_chunks);
    }
    if let Some(flow) = flow {
        let header_name = if item.finding.additional_sinks.is_empty() {
            item.finding.finding.sink.rule_id.clone()
        } else {
            format!(
                "{} (+{} sink)",
                item.finding.finding.sink.rule_id,
                item.finding.additional_sinks.len()
            )
        };
        let render_opts = crate::commands::InspectRenderOptions::default();
        let mut local_seen: crate::commands::BodySet = ahash::AHashSet::new();
        crate::commands::render_flow_block_with_heading(
            u,
            &render_opts,
            flow,
            &header_name,
            &mut local_seen,
            "TAINT FLOW",
        );
    } else {
        render_finding_block_compact(u, &item.finding, pack);
    }
    Ok(())
}

fn render_finding_continuation_header(
    u: &Ui,
    idx: usize,
    combined: &CombinedFindingWithChain,
    chunk: usize,
    total_chunks: usize,
) {
    let f = &combined.finding;
    let sev = f
        .severity
        .map_or_else(|| "-".to_string(), |s| s.as_str().to_string());
    let vuln_class = f.tag.as_deref().unwrap_or("vulnerability");
    cli_println!();
    cli_println!("{}", u.ruler('═', 70));
    cli_println!(
        "{} · {} · {}  {}",
        u.annotation(&format!("FINDING {idx} continued")),
        u.name(vuln_class),
        severity_cell(u, &sev),
        u.dim(&f.finding_id),
    );
    cli_println!(
        "  {}",
        u.dim(&format!("flow code part {chunk} of {total_chunks}"))
    );
    cli_println!("{}", u.ruler('─', 70));
}

fn taint_text_page_bounds(units: &[TaintTextUnit], page_payload_budget_bytes: u64) -> Vec<(usize, usize)> {
    if units.is_empty() {
        return vec![(0, 0)];
    }
    let mut bounds = Vec::new();
    let mut start = 0usize;
    while start < units.len() {
        let mut end = start;
        let mut bytes = 0u64;
        while end < units.len() {
            let cost = units[end].text.len() as u64;
            if end > start && bytes.saturating_add(cost) > page_payload_budget_bytes {
                break;
            }
            bytes = bytes.saturating_add(cost);
            end += 1;
        }
        if end == start {
            end += 1;
        }
        bounds.push((start, end));
        start = end;
    }
    bounds
}

fn resolve_taint_text_page(
    bounds: &[(usize, usize)],
    paging_cfg: &paging::PagingConfig,
    filters_hash: u64,
) -> Result<u64> {
    let total_pages = bounds.len().max(1) as u64;
    if let paging::PageArg::Number(requested) = &paging_cfg.page {
        paging::validate_page_number(*requested, total_pages, "security/taint-analysis")?;
    }
    let target = match &paging_cfg.page {
        paging::PageArg::First => 1,
        paging::PageArg::Number(n) => *n,
        paging::PageArg::Cursor(cursor) => {
            let offset = paging::resolve_cursor_offset(
                cursor,
                "security/taint-analysis",
                filters_hash,
                bounds.iter().map(|(start, _)| *start as u64),
            )?;
            bounds
                .iter()
                .position(|(start, _)| *start as u64 == offset)
                .map(|idx| idx as u64 + 1)
                .expect("resolved cursor offset must belong to page bounds")
        }
        paging::PageArg::Next => paging::last_cursor("security/taint-analysis", filters_hash)
            .and_then(|cursor| {
                bounds
                    .iter()
                    .position(|(start, _)| {
                        paging::cursor_id("security/taint-analysis", filters_hash, *start as u64) == cursor
                    })
                    .map(|idx| idx as u64 + 2)
            })
            .unwrap_or(1),
    };
    Ok(target.clamp(1, total_pages))
}

fn split_security_flow_for_context(
    flow: &crate::commands::InspectFlowRendered,
    target_bytes: u64,
) -> Vec<crate::commands::InspectFlowRendered> {
    let target = target_bytes.max(2_048);
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_cost = 0u64;
    for func in &flow.functions {
        for fragment in split_security_function_for_context(func, target) {
            let cost = security_function_cost_bytes(&fragment);
            if !current.is_empty() && current_cost.saturating_add(cost) > target {
                chunks.push(flow_chunk(flow, std::mem::take(&mut current)));
                current_cost = 0;
            }
            current_cost = current_cost.saturating_add(cost);
            current.push(fragment);
        }
    }
    if !current.is_empty() {
        chunks.push(flow_chunk(flow, current));
    }
    if chunks.is_empty() {
        chunks.push(flow.clone());
    }
    chunks
}

fn flow_chunk(
    flow: &crate::commands::InspectFlowRendered,
    functions: Vec<crate::commands::inspect::InspectFunctionRendered>,
) -> crate::commands::InspectFlowRendered {
    let mut chunk = flow.clone();
    chunk.functions = functions;
    chunk
}

fn split_security_function_for_context(
    func: &crate::commands::inspect::InspectFunctionRendered,
    target_bytes: u64,
) -> Vec<crate::commands::inspect::InspectFunctionRendered> {
    if func.lines.is_empty() {
        return vec![func.clone()];
    }
    let target = target_bytes.saturating_sub(768).max(512);
    let mut fragments = Vec::new();
    let mut current_lines = Vec::new();
    let mut current_cost = 0u64;
    for line in &func.lines {
        for line_part in split_security_line_for_context(line, target) {
            let cost = security_line_cost_bytes(&line_part);
            if !current_lines.is_empty() && current_cost.saturating_add(cost) > target {
                fragments.push(function_fragment(func, std::mem::take(&mut current_lines)));
                current_cost = 0;
            }
            current_cost = current_cost.saturating_add(cost);
            current_lines.push(line_part);
        }
    }
    if !current_lines.is_empty() {
        fragments.push(function_fragment(func, current_lines));
    }
    fragments
}

fn function_fragment(
    func: &crate::commands::inspect::InspectFunctionRendered,
    lines: Vec<crate::commands::inspect::InspectLine>,
) -> crate::commands::inspect::InspectFunctionRendered {
    let start_line = lines.first().map_or(func.start_line, |line| line.line_no);
    let end_line = lines.last().map_or(start_line, |line| line.line_no);
    let mut fragment = func.clone();
    fragment.start_line = start_line;
    fragment.end_line = end_line;
    fragment.lines = lines;
    fragment
}

fn split_security_line_for_context(
    line: &crate::commands::inspect::InspectLine,
    target_bytes: u64,
) -> Vec<crate::commands::inspect::InspectLine> {
    let max_text_bytes = target_bytes.saturating_sub(256).max(256) as usize;
    if line.text.len() <= max_text_bytes {
        return vec![line.clone()];
    }
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut part = 0usize;
    while start < line.text.len() {
        let mut end = (start + max_text_bytes).min(line.text.len());
        while end > start && !line.text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            end = line.text[start..]
                .char_indices()
                .nth(1)
                .map_or(line.text.len(), |(idx, _)| start + idx);
        }
        let mut next = line.clone();
        next.text = line.text[start..end].to_string();
        if part > 0 {
            next.step = None;
            next.annotation = Some("continued long source line".to_string());
        }
        out.push(next);
        start = end;
        part += 1;
    }
    out
}

fn security_function_cost_bytes(func: &crate::commands::inspect::InspectFunctionRendered) -> u64 {
    func.module_path.len() as u64
        + func.signature.len() as u64
        + func
            .owners
            .iter()
            .map(|owner| owner.kind.len() + owner.name.len() + 32)
            .sum::<usize>() as u64
        + func.lines.iter().map(security_line_cost_bytes).sum::<u64>()
        + 512
}

fn security_line_cost_bytes(line: &crate::commands::inspect::InspectLine) -> u64 {
    line.text.len() as u64 + line.annotation.as_deref().map_or(0, str::len) as u64 + 160
}

fn build_taint_render_report(
    report: TaintAnalysisReport,
    include_findings: bool,
    bulk_flow_evidence: bool,
) -> TaintAnalysisRenderReport {
    let summary = build_taint_summary(&report);
    if !include_findings {
        return TaintAnalysisRenderReport {
            summary,
            findings: Vec::new(),
            analysis_complete: report.analysis_complete,
            analysis_incomplete_reasons: report.analysis_incomplete_reasons,
            runtime_disabled_rules: report.runtime_disabled_rules,
            bulk_flow_evidence: false,
            baseline: None,
        };
    }
    let findings = report
        .findings
        .into_iter()
        .map(|finding| {
            let chain_func_ids = finding.chain_funcs.iter().map(|func| func.raw()).collect();
            TaintAnalysisRenderFinding {
                finding,
                chain_func_ids,
                baseline_status: None,
            }
        })
        .collect();
    TaintAnalysisRenderReport {
        summary,
        findings,
        analysis_complete: report.analysis_complete,
        analysis_incomplete_reasons: report.analysis_incomplete_reasons,
        runtime_disabled_rules: report.runtime_disabled_rules,
        bulk_flow_evidence,
        baseline: None,
    }
}

/// Load the set of stable finding ids from a previous `taint-analysis
/// --format json` output file, accepting both the bare findings array
/// and the `{ "rows": [...] }` paginated wrapper.
fn load_baseline_finding_ids(path: &Path) -> Result<std::collections::BTreeSet<String>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading baseline file {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing baseline JSON {}", path.display()))?;
    let rows = value
        .get("rows")
        .and_then(serde_json::Value::as_array)
        .or_else(|| value.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "baseline {} is not a taint-analysis findings array or {{rows: [...]}} object",
                path.display()
            )
        })?;
    Ok(rows
        .iter()
        .filter_map(|row| row.get("finding_id").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect())
}

/// Classify each current finding against the baseline ids, set its
/// `baseline_status`, and report the new/fixed/unchanged counts. `fixed`
/// = baseline findings with no current match.
fn apply_baseline(
    report: &mut TaintAnalysisRenderReport,
    baseline_ids: &std::collections::BTreeSet<String>,
) -> BaselineDiff {
    let mut current_ids = std::collections::BTreeSet::new();
    let (mut new, mut unchanged) = (0usize, 0usize);
    for item in &mut report.findings {
        let id = &item.finding.finding.finding_id;
        current_ids.insert(id.clone());
        if baseline_ids.contains(id) {
            unchanged += 1;
            item.baseline_status = Some("unchanged".to_string());
        } else {
            new += 1;
            item.baseline_status = Some("new".to_string());
        }
    }
    let fixed_finding_ids: Vec<String> = baseline_ids
        .iter()
        .filter(|id| !current_ids.contains(*id))
        .cloned()
        .collect();
    BaselineDiff {
        new,
        fixed: fixed_finding_ids.len(),
        unchanged,
        fixed_finding_ids,
    }
}

/// `--explain`: diagnose why a `--source`/`--sink` pair does or does not
/// connect. Composes the source-site and sink-site inventories with the
/// taint result so the report distinguishes the two failure modes a
/// reviewer actually needs to tell apart — "the rule matched nothing"
/// vs "the rule matched but the value never flows".
#[allow(clippy::too_many_arguments)]
fn emit_taint_explain(
    project: &bonsai_sdk::Project,
    source: Option<&str>,
    sink: Option<&str>,
    trust: Option<&str>,
    category: Option<&str>,
    severity: Option<Severity>,
    tag: Option<&str>,
    files: &[String],
    exclude_files: &[String],
    report: &TaintAnalysisReport,
    format: SecurityFormat,
) -> Result<()> {
    let source_sites = project.security().sources(SecurityInventoryOptions {
        rule_regex: source.map(str::to_string),
        trust: trust.map(str::to_string),
        category: category.map(str::to_string),
        files: files.to_vec(),
        exclude_files: exclude_files.to_vec(),
        ..Default::default()
    })?;
    let sink_sites = project.security().sinks(SecurityInventoryOptions {
        rule_regex: sink.map(str::to_string),
        severity,
        tag: tag.map(str::to_string),
        files: files.to_vec(),
        exclude_files: exclude_files.to_vec(),
        ..Default::default()
    })?;
    let taint_paths = report.findings.len();

    // Verdict: first failing gate wins. `--source` / `--sink` are
    // optional, so an empty result only counts as a gate failure when
    // the corresponding filter was actually requested.
    let (verdict, message) = if source.is_some() && source_sites.is_empty() {
        (
            "no-source-match",
            format!(
                "no source site matched `{}` in this workspace — the source rule never fired, so no flow could begin.",
                source.unwrap_or("")
            ),
        )
    } else if sink.is_some() && sink_sites.is_empty() {
        (
            "no-sink-match",
            format!(
                "no sink site matched `{}` in this workspace — the sink rule never fired, so there is nothing to reach.",
                sink.unwrap_or("")
            ),
        )
    } else if taint_paths > 0 {
        (
            "connected",
            format!(
                "source and sink are connected by {taint_paths} taint path(s). Drop --explain to see the flow(s)."
            ),
        )
    } else {
        (
            "no-path",
            "source and sink both matched, but no taint path links them — the value does not flow end-to-end. \
             Common causes: an intervening sanitizer credited the value, a broken assignment / alias chain, or a \
             cross-function boundary the engine cannot follow. Re-run with BONSAI_DEBUG=security-taint for the \
             per-source IDG cut detail."
                .to_string(),
        )
    };

    if matches!(format, SecurityFormat::Json) {
        let preview = |sites: &[RuleMatch]| {
            sites
                .iter()
                .take(5)
                .map(|m| {
                    serde_json::json!({
                        "rule_id": m.rule_id,
                        "file": m.file,
                        "line": m.line,
                        "column": m.column,
                    })
                })
                .collect::<Vec<_>>()
        };
        let out = serde_json::json!({
            "explain": {
                "source": source,
                "sink": sink,
                "source_sites": source_sites.len(),
                "sink_sites": sink_sites.len(),
                "taint_paths": taint_paths,
                "verdict": verdict,
                "message": message,
                "source_site_preview": preview(&source_sites),
                "sink_site_preview": preview(&sink_sites),
            }
        });
        cli_println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let u = ui();
    cli_println!(
        "{}",
        u.dim(&format!(
            "explain  {} → {}",
            source.unwrap_or("<any source>"),
            sink.unwrap_or("<any sink>")
        ))
    );
    let mut table = u.table(&["stage", "count"]);
    table.add_row(vec![
        Cell::new("source sites matched"),
        Cell::new(source_sites.len()),
    ]);
    table.add_row(vec![Cell::new("sink sites matched"), Cell::new(sink_sites.len())]);
    table.add_row(vec![Cell::new("taint paths"), Cell::new(taint_paths)]);
    cli_println!("{table}");
    let mark = if verdict == "connected" {
        u.name("✓ CONNECTED")
    } else {
        u.warn("✗ NOT CONNECTED")
    };
    cli_println!();
    cli_println!("  {}  {}", mark, message);
    Ok(())
}

/// Append the text baseline summary inside the cached page payload so an
/// identical warm replay preserves the exact same user-visible report.
fn render_baseline_summary_text(diff: &BaselineDiff) {
    let u = ui();
    cli_println!();
    cli_println!(
        "{}",
        u.dim(&format!(
            "baseline diff — {} new · {} fixed · {} unchanged",
            diff.new, diff.fixed, diff.unchanged
        ))
    );
}

fn build_taint_summary(report: &TaintAnalysisReport) -> TaintAnalysisSummary {
    summarize_taint_findings(
        report.findings.iter(),
        report.findings.len(),
        report.source_rule_count,
        report.sink_rule_count,
        report.sanitizer_rule_count,
        report.analysis_complete,
        report.analysis_incomplete_reasons.clone(),
    )
}

/// Build the aggregate summary from any sequence of findings. Shared
/// between the fresh-analysis path (counts the full result) and the
/// secondary-filter render path (counts only the findings that survive
/// `--contains` / `--not-contains`), so `--summary --contains X`
/// reports counts for the filtered set. Rule counts come from the
/// analysis (they describe the loaded rulepack, not the result) and
/// are passed through unchanged.
fn summarize_taint_findings<'a>(
    findings: impl Iterator<Item = &'a CombinedFindingWithChain>,
    total_findings: usize,
    source_rule_count: usize,
    sink_rule_count: usize,
    sanitizer_rule_count: usize,
    analysis_complete: bool,
    analysis_incomplete_reasons: Vec<String>,
) -> TaintAnalysisSummary {
    let mut summary = TaintAnalysisSummary {
        analysis_complete,
        analysis_incomplete_reasons,
        total_findings,
        source_rule_count,
        sink_rule_count,
        sanitizer_rule_count,
        severity_counts: BTreeMap::new(),
        status_counts: BTreeMap::new(),
        precision_counts: BTreeMap::new(),
        tag_counts: BTreeMap::new(),
        language_counts: BTreeMap::new(),
        source_rule_counts: BTreeMap::new(),
        sink_rule_counts: BTreeMap::new(),
        source_trust_counts: BTreeMap::new(),
        source_category_counts: BTreeMap::new(),
        sink_file_counts: BTreeMap::new(),
    };
    for item in findings {
        let finding = &item.finding;
        inc_count(
            &mut summary.severity_counts,
            finding.severity.map_or("none", |severity| severity.as_str()),
        );
        inc_count(&mut summary.status_counts, finding.status.as_str());
        inc_count(&mut summary.precision_counts, &finding.precision);
        inc_count(
            &mut summary.tag_counts,
            finding.tag.as_deref().unwrap_or("untagged"),
        );
        inc_count(&mut summary.language_counts, &finding.language);
        inc_count(&mut summary.source_rule_counts, &finding.source.rule_id);
        for source in &item.additional_sources {
            inc_count(&mut summary.source_rule_counts, &source.rule_id);
        }
        inc_count(&mut summary.sink_rule_counts, &finding.sink.rule_id);
        for sink in &item.additional_sinks {
            inc_count(&mut summary.sink_rule_counts, &sink.rule_id);
        }
        inc_count(
            &mut summary.source_trust_counts,
            finding.source.trust.as_deref().unwrap_or("unknown"),
        );
        inc_count(
            &mut summary.source_category_counts,
            finding.source.category.as_deref().unwrap_or("unknown"),
        );
        inc_count(&mut summary.sink_file_counts, &finding.sink.file);
    }
    summary
}

fn inc_count(counts: &mut BTreeMap<String, usize>, key: &str) {
    *counts.entry(key.to_string()).or_insert(0) += 1;
}

/// Keep only the findings whose serialized string-values satisfy the
/// active `--contains` / `--not-contains` filter, and recompute the
/// summary over the survivors. Matches on the finding's JSON values
/// (source/sink rule ids, files, code text, chain) — what a developer
/// greps for. Returns a fresh owned report; the caller keeps the
/// original for caching.
fn filter_taint_render_report(report: &TaintAnalysisRenderReport) -> TaintAnalysisRenderReport {
    let secondary = crate::filter::active();
    let findings: Vec<TaintAnalysisRenderFinding> = report
        .findings
        .iter()
        .filter(|rf| secondary.matches_value(&rf.finding))
        .cloned()
        .collect();
    let summary = summarize_taint_findings(
        findings.iter().map(|rf| &rf.finding),
        findings.len(),
        report.summary.source_rule_count,
        report.summary.sink_rule_count,
        report.summary.sanitizer_rule_count,
        report.analysis_complete,
        report.analysis_incomplete_reasons.clone(),
    );
    TaintAnalysisRenderReport {
        summary,
        findings,
        analysis_complete: report.analysis_complete,
        analysis_incomplete_reasons: report.analysis_incomplete_reasons.clone(),
        runtime_disabled_rules: report.runtime_disabled_rules.clone(),
        bulk_flow_evidence: report.bulk_flow_evidence,
        baseline: None,
    }
}

fn flow_from_finding_hops(
    finding: &CombinedFindingWithChain,
    idx: usize,
) -> Option<crate::commands::InspectFlowRendered> {
    if finding.finding.hops.is_empty() {
        return None;
    }
    let flow_number = u32::try_from(idx + 1).unwrap_or(u32::MAX);
    let flow_label = (idx + 1).to_string();
    let chain = if finding.finding.chain_display.is_empty() {
        finding
            .finding
            .hops
            .iter()
            .map(|hop| hop.function.clone())
            .collect::<Vec<_>>()
    } else {
        finding.finding.chain_display.clone()
    };
    let functions = finding
        .finding
        .hops
        .iter()
        .map(|hop| crate::commands::inspect::InspectFunctionRendered {
            module_path: hop.file.clone(),
            owners: Vec::new(),
            name: hop.function.clone(),
            signature: hop.function.clone(),
            start_line: hop.start_line,
            end_line: hop.lines.last().map_or(hop.start_line, |line| line.n),
            lines: hop
                .lines
                .iter()
                .map(|line| crate::commands::inspect::InspectLine {
                    line_no: line.n,
                    text: line.text.clone(),
                    step: None,
                    annotation: None,
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    let mut flow = crate::commands::InspectFlowRendered {
        flow_number,
        flow_label,
        flow_id: finding
            .finding
            .representative_flow_id
            .clone()
            .unwrap_or_else(|| finding.finding.finding_id.clone()),
        chain_display: chain.join(" -> "),
        chain,
        precision: precision_from_finding_label(&finding.finding.precision),
        functions,
    };
    annotate_taint_flow(
        &mut flow,
        &finding.finding.source,
        &finding.additional_sources,
        &finding.finding.taint_path,
        Some(&finding.finding.sink),
        SecurityFlowKind::Taint,
    );
    Some(flow)
}

fn render_taint_summary_text(summary: &TaintAnalysisSummary) {
    let u = ui();
    cli_println!(
        "{}",
        u.dim(&format!(
            "security taint-analysis summary — {} finding(s)",
            summary.total_findings
        ))
    );
    if summary.analysis_complete {
        cli_println!("{}", u.dim("analysis: complete"));
    } else {
        let reasons = if summary.analysis_incomplete_reasons.is_empty() {
            "unknown semantic coverage gap".to_string()
        } else {
            summary.analysis_incomplete_reasons.join(", ")
        };
        cli_println!("{}", u.warn(&format!("analysis incomplete — {reasons}")));
    }
    let mut overview = u.table(&["metric", "count"]);
    overview.add_row(vec![Cell::new("findings"), Cell::new(summary.total_findings)]);
    overview.add_row(vec![
        Cell::new("source rules"),
        Cell::new(summary.source_rule_count),
    ]);
    overview.add_row(vec![Cell::new("sink rules"), Cell::new(summary.sink_rule_count)]);
    overview.add_row(vec![
        Cell::new("sanitizer rules"),
        Cell::new(summary.sanitizer_rule_count),
    ]);
    cli_println!("{overview}");
    render_count_table(u, "tags", "tag", &summary.tag_counts, 20);
    render_count_table(u, "severities", "severity", &summary.severity_counts, 10);
    render_count_table(u, "statuses", "status", &summary.status_counts, 10);
    render_count_table(u, "precision", "precision", &summary.precision_counts, 10);
    render_count_table(u, "sink rules", "sink", &summary.sink_rule_counts, 20);
    render_count_table(u, "source rules", "source", &summary.source_rule_counts, 20);
    render_count_table(u, "languages", "language", &summary.language_counts, 20);
}

fn render_count_table(u: &Ui, title: &str, key_header: &str, counts: &BTreeMap<String, usize>, limit: usize) {
    if counts.is_empty() {
        return;
    }
    cli_println!();
    cli_println!("{}", u.dim(title));
    let mut table = u.table(&[key_header, "count"]);
    for (key, count) in sorted_counts(counts).into_iter().take(limit) {
        table.add_row(vec![Cell::new(u.name(key)), Cell::new(*count)]);
    }
    cli_println!("{table}");
}

fn sorted_counts(counts: &BTreeMap<String, usize>) -> Vec<(&String, &usize)> {
    let mut rows: Vec<_> = counts.iter().collect();
    rows.sort_by(|(left_key, left_count), (right_key, right_count)| {
        right_count.cmp(left_count).then_with(|| left_key.cmp(right_key))
    });
    rows
}

fn top_counts_json(counts: &BTreeMap<String, usize>, limit: usize) -> serde_json::Value {
    serde_json::Value::Array(
        sorted_counts(counts)
            .into_iter()
            .take(limit)
            .map(|(key, count)| {
                serde_json::json!({
                    "key": key,
                    "count": count,
                })
            })
            .collect(),
    )
}

fn compact_taint_summary(summary: &TaintAnalysisSummary) -> serde_json::Value {
    serde_json::json!({
        "kind": "compact",
        "analysis_complete": summary.analysis_complete,
        "analysis_incomplete_reasons": summary.analysis_incomplete_reasons,
        "total_findings": summary.total_findings,
        "source_rule_count": summary.source_rule_count,
        "sink_rule_count": summary.sink_rule_count,
        "sanitizer_rule_count": summary.sanitizer_rule_count,
        "severity_counts": summary.severity_counts,
        "status_counts": summary.status_counts,
        "precision_counts": summary.precision_counts,
        "tag_counts": summary.tag_counts,
        "language_counts": summary.language_counts,
        "source_trust_counts": summary.source_trust_counts,
        "source_category_counts": summary.source_category_counts,
        "source_rule_distinct": summary.source_rule_counts.len(),
        "sink_rule_distinct": summary.sink_rule_counts.len(),
        "sink_file_distinct": summary.sink_file_counts.len(),
        "top_source_rules": top_counts_json(&summary.source_rule_counts, 20),
        "top_sink_rules": top_counts_json(&summary.sink_rule_counts, 20),
        "top_sink_files": top_counts_json(&summary.sink_file_counts, 20),
    })
}

fn taint_json_cost_bytes(item: &TaintAnalysisRenderFinding) -> u64 {
    serde_json::to_vec(item)
        .map(|bytes| bytes.len() as u64)
        .unwrap_or_else(|_| taint_text_cost_bytes_without_pack(item))
}

fn taint_path_cost_bytes(taint_path: &[TaintPropagationStep]) -> u64 {
    taint_path
        .iter()
        .map(|step| {
            step.caller.len()
                + step.callee.len()
                + step.file.len()
                + step
                    .tainted_args
                    .iter()
                    .map(|arg| arg.value_text.len() + arg.param_name.len() + 16)
                    .sum::<usize>()
        })
        .sum::<usize>() as u64
}

fn taint_text_cost_bytes_without_pack(item: &TaintAnalysisRenderFinding) -> u64 {
    let mut bytes = finding_shallow_cost_bytes(&item.finding).saturating_add(1800);
    if !item.finding.finding.hops.is_empty() {
        for hop in &item.finding.finding.hops {
            bytes = bytes
                .saturating_add(hop.file.len() as u64)
                .saturating_add(hop.function.len() as u64)
                .saturating_add(240);
            for line in &hop.lines {
                bytes = bytes.saturating_add(line.text.len() as u64).saturating_add(40);
            }
        }
    } else {
        bytes = bytes.saturating_add(taint_path_cost_bytes(&item.finding.finding.taint_path));
    }
    bytes
}

fn finding_shallow_cost_bytes(f: &CombinedFindingWithChain) -> u64 {
    (f.finding.source.file.len()
        + f.finding.sink.file.len()
        + f.finding.source.text.len().min(120)
        + f.finding.sink.text.len().min(120)
        + f.finding.tag.as_deref().map_or(0, str::len)
        + f.finding.finding_id.len()
        + f.additional_sources
            .iter()
            .map(|s| s.rule_id.len() + s.file.len() + s.text.len().min(120))
            .sum::<usize>()
        + f.additional_sinks
            .iter()
            .map(|s| s.rule_id.len() + s.file.len() + s.text.len().min(120))
            .sum::<usize>()
        + 512) as u64
}

// ---- source-analysis — downstream taint/call map from all source seeds ----
#[derive(Serialize, Clone)]
struct CombinedSourceAnalysisFlow {
    source: FindingMatch,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    additional_sources: Vec<FindingMatch>,
    analysis_complete: bool,
    analysis_incomplete_reasons: Vec<String>,
    lineage: SourceLineageStatus,
    flow: crate::commands::InspectFlowRendered,
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
fn cmd_source_analysis(
    workspace: &Path,
    pack: &Rulepack,
    rules_dir: &Path,
    source: Option<String>,
    trust: Option<String>,
    tag: Option<String>,
    category: Option<String>,
    files: Vec<String>,
    exclude_files: Vec<String>,
    exclude_tests: bool,
    inferred_sources: bool,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = if !files.is_empty() || !exclude_files.is_empty() {
        open_security_project_filtered_paths(workspace, pack, rules_dir, &files, &exclude_files)?
    } else {
        open_security_project(workspace, pack, rules_dir)?
    };
    let ws = project.workspace();
    let mut analysis_progress = SecurityAnalysisProgress::new();
    let report = project.security().source_analysis_with_phase_progress(
        SourceAnalysisOptions {
            source: source.clone(),
            trust: trust.clone(),
            category: category.clone(),
            tag: tag.clone(),
            files: files.clone(),
            exclude_files: exclude_files.clone(),
            exclude_tests,
            include_inferred_sources: inferred_sources,
            lineage_limits: if paging_cfg.all {
                bonsai_sdk::SourceLineageLimits::unbounded()
            } else {
                bonsai_sdk::SourceLineageLimits::bounded_default()
            },
        },
        |event| analysis_progress.handle(event),
    )?;
    let source_rule_count = report.source_rule_count;
    let lineage_summary = report.lineage_summary;
    let report_analysis_complete = report.analysis_complete;
    let mut report_analysis_incomplete_reasons = report.analysis_incomplete_reasons;
    let report_runtime_disabled_rules = report.runtime_disabled_rules;
    if !report_analysis_complete && report_analysis_incomplete_reasons.is_empty() {
        report_analysis_incomplete_reasons.push("source-analysis incomplete: unknown reason".to_string());
    }
    // Secondary `--contains` / `--not-contains` filter, applied once to
    // the candidate set that every render path (text + json) draws from.
    let mut candidates = report.candidates;
    crate::filter::active().retain(&mut candidates);

    let filters_hash = filter_signature(&[
        ("kind", "source-analysis"),
        ("source", source.as_deref().unwrap_or("")),
        ("trust", trust.as_deref().unwrap_or("")),
        ("category", category.as_deref().unwrap_or("")),
        ("tag", tag.as_deref().unwrap_or("")),
    ]);
    let cost = |f: &CombinedSourceAnalysisCandidate| {
        (1200
            + f.source.rule_id.len()
            + f.source.file.len()
            + f.source.text.len().min(160)
            + f.additional_sources
                .iter()
                .map(|s| s.rule_id.len() + s.file.len() + s.text.len().min(160) + 256)
                .sum::<usize>()
            + f.chain_names.iter().map(|n| n.len() + 16).sum::<usize>()) as u64
    };

    match format {
        BrowseFormat::Json => {
            // Security JSON always carries scan completeness, including
            // `--all`; an empty bare array would be ambiguous to automation.
            page_cache::emit_paged_text(
                workspace,
                &candidates,
                &paging_cfg,
                "security/source-analysis",
                filters_hash,
                cost,
                |paged, info, _cfg| {
                    let rendered = render_source_analysis_candidates(ws, paged);
                    let analysis_incomplete_reasons = source_analysis_json_incomplete_reasons(
                        "security/source-analysis",
                        info,
                        &rendered,
                        &report_analysis_incomplete_reasons,
                    );
                    let wrapped = serde_json::json!({
                        "analysis_complete": report_analysis_complete
                            && analysis_incomplete_reasons.is_empty(),
                        "analysis_incomplete_reasons": analysis_incomplete_reasons,
                        "runtime_disabled_rules": &report_runtime_disabled_rules,
                        "rows": rendered,
                        "summary": {
                            "source_flow_count": candidates.len(),
                            "source_rule_count": source_rule_count,
                            "lineage": lineage_summary,
                        },
                        "page": page_info_to_json(info),
                    });
                    cli_println!("{}", serde_json::to_string_pretty(&wrapped)?);
                    Ok(())
                },
            )?;
            Ok(())
        }
        BrowseFormat::Text => {
            let cost_progress = ScopedProgress::new("estimating source page costs");
            let function_costs =
                function_costs_for_paths(ws, candidates.iter().flat_map(|c| c.path.iter().copied()), true);
            cost_progress.finish();
            let text_cost = |f: &CombinedSourceAnalysisCandidate| {
                source_analysis_text_cost_bytes(f, pack, &function_costs) + paging::TABLE_ROW_CHROME_BYTES
            };
            let pagination_progress = ScopedProgress::new("paginating source flows");
            let (_current, current_info) = paging::paginate(
                &candidates,
                &paging_cfg,
                "security/source-analysis",
                filters_hash,
                text_cost,
            )?;
            let total_pages = current_info.total_pages;
            let current_page = current_info.page_number;
            pagination_progress.finish();
            let page_render_progress = ScopedProgress::new("rendering source page window");
            let mut cached_pages = Vec::new();
            for page_number in page_cache::eager_window(current_page, total_pages) {
                let mut page_cfg = paging_cfg.clone();
                page_cfg.page = paging::PageArg::Number(page_number);
                let (paged, info) = paging::paginate(
                    &candidates,
                    &page_cfg,
                    "security/source-analysis",
                    filters_hash,
                    text_cost,
                )?;
                let text = page_cache::capture(|| {
                    render_source_analysis_text_page(
                        ws,
                        pack,
                        &paged,
                        &info,
                        candidates.len(),
                        source_rule_count,
                        lineage_summary,
                        report_analysis_complete,
                        &report_analysis_incomplete_reasons,
                        &report_runtime_disabled_rules,
                    )
                })?;
                cached_pages.push(page_cache::CachedPage {
                    number: page_number,
                    cursor: info.cursor,
                    text,
                });
            }
            page_render_progress.finish();
            let _ = paging::paginate(
                &candidates,
                &paging_cfg,
                "security/source-analysis",
                filters_hash,
                text_cost,
            )?;
            let cache_progress = ScopedProgress::new("saving source page cache");
            if let Err(e) = page_cache::save_pages(
                workspace,
                "security/source-analysis",
                filters_hash,
                cached_pages.clone(),
            ) {
                tracing::debug!("page cache save failed: {e}");
            }
            cache_progress.finish();
            if let Some(page) = cached_pages.iter().find(|p| p.number == current_page) {
                page_cache::emit_cached_text(&page.text)?;
            }
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)] // Renderer state is explicit to keep pagination metadata visible at call sites.
fn render_source_analysis_text_page(
    ws: &bonsai_sdk::Workspace,
    pack: &Rulepack,
    candidates: &[CombinedSourceAnalysisCandidate],
    info: &paging::PageInfo,
    total_candidates: usize,
    source_rule_count: usize,
    lineage_summary: SourceLineageSummary,
    report_analysis_complete: bool,
    report_analysis_incomplete_reasons: &[String],
    runtime_disabled_rules: &[RuntimeDisabledRule],
) -> Result<()> {
    let rendered = render_source_analysis_candidates(ws, candidates);
    let u = ui();
    cli_println!(
        "{}",
        u.dim(&format!(
            "security source-analysis — {} source flow(s) · {} source rule(s) loaded",
            total_candidates, source_rule_count,
        ))
    );
    if report_analysis_complete {
        cli_println!("{}", u.dim("analysis: complete"));
    } else {
        let reason = if report_analysis_incomplete_reasons.is_empty() {
            "unknown scan coverage gap".to_string()
        } else {
            report_analysis_incomplete_reasons.join(", ")
        };
        for line in u.wrapped_warn_labeled_lines("analysis incomplete", &reason) {
            cli_println!("{line}");
        }
    }
    for disabled in runtime_disabled_rules {
        cli_println!(
            "{}",
            u.warn(&format!(
                "runtime-disabled rule {} — {}",
                disabled.rule_id, disabled.reason
            ))
        );
    }
    if !lineage_summary.is_complete() {
        let reason = format!(
            "{} representative flow(s); {} truncated by hop budget; {} additional path(s) omitted; max {} hop(s), {} path(s) rendered per flow",
            lineage_summary.incomplete_flows,
            lineage_summary.truncated_hop_flows,
            lineage_summary.omitted_paths,
            lineage_summary.max_hops,
            lineage_summary.max_paths,
        );
        for line in u.wrapped_warn_labeled_lines("lineage incomplete", &reason) {
            cli_println!("{line}");
        }
    }
    let render_opts = crate::commands::InspectRenderOptions::default();
    for item in rendered.iter() {
        render_source_analysis_header(u, item.flow.flow_number as usize, item, pack);
        let mut local_seen: crate::commands::BodySet = ahash::AHashSet::new();
        crate::commands::render_flow_block_with_heading(
            u,
            &render_opts,
            &item.flow,
            &item.source.rule_id,
            &mut local_seen,
            "SOURCE FLOW",
        );
    }
    render_paging_footer(info, "bonsai-ninja security <workspace> source-analysis");
    Ok(())
}

fn render_source_analysis_candidates(
    ws: &bonsai_sdk::Workspace,
    candidates: &[CombinedSourceAnalysisCandidate],
) -> Vec<CombinedSourceAnalysisFlow> {
    candidates
        .iter()
        .enumerate()
        .filter_map(|(idx, item)| render_source_analysis_candidate(ws, idx, item))
        .collect()
}

fn render_source_analysis_candidate(
    ws: &bonsai_sdk::Workspace,
    idx: usize,
    item: &CombinedSourceAnalysisCandidate,
) -> Option<CombinedSourceAnalysisFlow> {
    let label = (idx + 1).to_string();
    let call_spans = security_flow_call_spans(ws, &item.path, &item.chain_names, &item.taint_path);
    let mut flow = crate::commands::render_flow_with_cached_call_spans(
        ws,
        &item.path,
        &call_spans,
        (idx + 1) as u32,
        &label,
        item.precision,
        None,
        crate::commands::InspectFilters::default(),
        false,
        false,
    )?;
    flow.flow_id.clone_from(&item.flow_id);
    annotate_taint_flow(
        &mut flow,
        &item.source,
        &item.additional_sources,
        &item.taint_path,
        None,
        SecurityFlowKind::Source,
    );
    Some(CombinedSourceAnalysisFlow {
        source: item.source.clone(),
        additional_sources: item.additional_sources.clone(),
        analysis_complete: item.lineage.is_complete_default(),
        analysis_incomplete_reasons: source_lineage_incomplete_reasons(item.lineage),
        lineage: item.lineage,
        flow,
    })
}

fn source_lineage_incomplete_reasons(lineage: SourceLineageStatus) -> Vec<String> {
    let mut reasons = Vec::new();
    if lineage.truncated_hops {
        reasons.push(format!("lineage truncated to {} hops", lineage.max_hops));
    }
    if lineage.omitted_paths > 0 {
        reasons.push(format!(
            "{} additional lineage path(s) omitted",
            lineage.omitted_paths
        ));
    }
    if !lineage.is_complete_default() && reasons.is_empty() {
        reasons.push("lineage incomplete".to_string());
    }
    reasons
}

fn security_flow_call_spans(
    ws: &bonsai_sdk::Workspace,
    path: &[FuncId],
    chain_names: &[String],
    taint_path: &[TaintPropagationStep],
) -> Vec<Option<Span>> {
    if path.is_empty() {
        return Vec::new();
    }
    let mut spans = vec![None; path.len()];
    let mut step_cursor = 0usize;
    for (edge_idx, span_slot) in spans.iter_mut().enumerate().take(path.len().saturating_sub(1)) {
        let Some(caller) = chain_names.get(edge_idx) else {
            continue;
        };
        let Some(callee) = chain_names.get(edge_idx + 1) else {
            continue;
        };
        let Some((step_idx, step)) = taint_path
            .iter()
            .enumerate()
            .skip(step_cursor)
            .find(|(_, step)| &step.caller == caller && &step.callee == callee)
        else {
            continue;
        };
        *span_slot = span_for_render_location(ws, &step.file, step.line, step.column);
        step_cursor = step_idx + 1;
    }
    spans
}

fn span_for_render_location(ws: &bonsai_sdk::Workspace, file: &str, line: u32, column: u32) -> Option<Span> {
    let file_id = ws.vfs().lookup(Path::new(file)).or_else(|| {
        ws.vfs().all_files().into_iter().find(|&candidate| {
            ws.vfs()
                .path(candidate)
                .ok()
                .is_some_and(|path| same_rendered_file(&path.display().to_string(), file))
        })
    })?;
    let snapshot = ws.vfs().snapshot(file_id).ok()?;
    let offset = byte_offset_for_line_col(snapshot.text.as_ref(), line, column)?;
    Some(Span::empty(file_id, offset))
}

fn byte_offset_for_line_col(text: &str, line: u32, column: u32) -> Option<u64> {
    if line == 0 || column == 0 {
        return None;
    }
    let mut line_start = 0usize;
    let mut current_line = 1u32;
    while current_line < line {
        let rel_newline = text.get(line_start..)?.find('\n')?;
        line_start = line_start.saturating_add(rel_newline).saturating_add(1);
        current_line += 1;
    }
    let line_end = text
        .get(line_start..)
        .and_then(|tail| tail.find('\n').map(|rel| line_start + rel))
        .unwrap_or(text.len());
    let wanted = line_start
        .saturating_add(usize::try_from(column.saturating_sub(1)).ok()?)
        .min(line_end);
    Some(u64::try_from(wanted).unwrap_or(u64::MAX))
}

#[derive(Copy, Clone)]
enum SecurityFlowKind {
    Taint,
    Source,
}

impl SecurityFlowKind {
    fn heading(self) -> &'static str {
        match self {
            Self::Taint => "TAINT FLOW",
            Self::Source => "SOURCE FLOW",
        }
    }
}

fn annotate_taint_flow(
    flow: &mut crate::commands::InspectFlowRendered,
    source: &FindingMatch,
    additional_sources: &[FindingMatch],
    taint_path: &[TaintPropagationStep],
    sink: Option<&FindingMatch>,
    kind: SecurityFlowKind,
) {
    for func in &mut flow.functions {
        for line in &mut func.lines {
            line.step = None;
            line.annotation = None;
        }
    }

    let label = flow.flow_label.clone();
    let mut step_counter = 0u32;
    let mut sources: Vec<&FindingMatch> = Vec::with_capacity(1 + additional_sources.len());
    sources.push(source);
    sources.extend(additional_sources);
    sources.sort_by(|a, b| {
        (a.file.as_str(), a.line, a.column, a.rule_id.as_str()).cmp(&(
            b.file.as_str(),
            b.line,
            b.column,
            b.rule_id.as_str(),
        ))
    });
    for source in sources {
        let marker = format!("SOURCE: {} {}", source.rule_id, truncate_text(&source.text, 80));
        add_flow_line_annotation(
            flow,
            &source.file,
            source.line,
            &label,
            marker,
            kind,
            &mut step_counter,
        );
    }

    let mut sink_annotated = false;
    for step in taint_path {
        let is_sink =
            sink.is_some_and(|sink| same_rendered_file(&step.file, &sink.file) && step.line == sink.line);
        if is_sink {
            sink_annotated = true;
        }
        let marker = if is_sink {
            let sink_rule = sink.map(|sink| sink.rule_id.as_str()).unwrap_or("sink");
            format!("SINK: {sink_rule} {}", format_taint_args(&step.tainted_args))
        } else {
            format!(
                "TAINT: {} -> {} {}",
                step.caller,
                step.callee,
                format_taint_args(&step.tainted_args)
            )
        };
        add_flow_line_annotation(
            flow,
            &step.file,
            step.line,
            &label,
            marker,
            kind,
            &mut step_counter,
        );
    }

    if let Some(sink) = sink {
        if !sink_annotated {
            let marker = format!("SINK: {} {}", sink.rule_id, format_sink_args(sink));
            add_flow_line_annotation(
                flow,
                &sink.file,
                sink.line,
                &label,
                marker,
                kind,
                &mut step_counter,
            );
        }
    }
}

fn add_flow_line_annotation(
    flow: &mut crate::commands::InspectFlowRendered,
    file: &str,
    line_no: u32,
    flow_label: &str,
    marker: String,
    kind: SecurityFlowKind,
    step_counter: &mut u32,
) {
    for func in &mut flow.functions {
        if !same_rendered_file(&func.module_path, file) {
            continue;
        }
        let Some(line) = func.lines.iter_mut().find(|line| line.line_no == line_no) else {
            continue;
        };
        if line.step.is_none() {
            *step_counter += 1;
            line.step = Some(*step_counter);
        }
        let annotation = format!("[{} {flow_label} {marker}]", kind.heading());
        match line.annotation.as_mut() {
            Some(existing) => {
                existing.push(' ');
                existing.push_str(&annotation);
            }
            None => line.annotation = Some(annotation),
        }
        return;
    }
}

fn same_rendered_file(rendered: &str, target: &str) -> bool {
    if rendered == target {
        return true;
    }
    let rendered = rendered.replace('\\', "/");
    let target = target.replace('\\', "/");
    rendered == target
        || rendered.ends_with(&format!("/{target}"))
        || target.ends_with(&format!("/{rendered}"))
}

fn format_taint_args(args: &[TaintPropagationArg]) -> String {
    if args.is_empty() {
        return "tainted value".to_string();
    }
    args.iter()
        .map(|arg| {
            if arg.index == usize::MAX {
                if arg.param_name.is_empty() {
                    format!("receiver {}", arg.value_text)
                } else {
                    format!("receiver {} -> {}", arg.value_text, arg.param_name)
                }
            } else if arg.param_name.is_empty() {
                format!("arg[{}] {}", arg.index, arg.value_text)
            } else {
                format!("arg[{}] {} -> {}", arg.index, arg.value_text, arg.param_name)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_sink_args(sink: &FindingMatch) -> String {
    if sink.tainted_args.is_empty() {
        return "tainted value".to_string();
    }
    sink.tainted_args
        .iter()
        .map(|arg| format!("arg[{}] {}", arg.index, arg.value_text))
        .collect::<Vec<_>>()
        .join(", ")
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let suffix = "...";
    let take = max_chars.saturating_sub(suffix.len());
    let mut out = text.chars().take(take).collect::<String>();
    out.push_str(suffix);
    out
}

fn render_source_analysis_header(u: &Ui, idx: usize, item: &CombinedSourceAnalysisFlow, pack: &Rulepack) {
    let source = &item.source;
    cli_println!();
    cli_println!("{}", u.ruler('═', 70));
    cli_println!(
        "{} · {}  {}",
        u.annotation(&format!("SOURCE FLOW {idx}")),
        u.name(source.tag.as_deref().unwrap_or("source")),
        u.dim(&source.rule_id),
    );
    if !item.additional_sources.is_empty() {
        cli_println!(
            "  {}    {}",
            u.dim("sources:"),
            u.dim(&(1 + item.additional_sources.len()).to_string())
        );
    }
    if !item.lineage.is_complete_default() {
        let parts = source_lineage_incomplete_reasons(item.lineage);
        cli_println!(
            "  {}   {}",
            u.dim("lineage:"),
            u.warn(&format!("representative ({})", parts.join("; ")))
        );
    }
    render_source_analysis_source(u, source, pack);
    for source in &item.additional_sources {
        render_source_analysis_source(u, source, pack);
    }
}

fn render_source_analysis_source(u: &Ui, source: &FindingMatch, pack: &Rulepack) {
    cli_println!();
    cli_println!("  {} {}", u.kind("SOURCE:"), u.name(&source.rule_id));
    let loc = format!("{}:{}:{}", short_file(&source.file), source.line, source.column);
    cli_println!("    {}   {}", u.dim("where:"), u.path(&loc));
    if let Some(trust) = source.trust.as_deref() {
        cli_println!("    {}   {}", u.dim("trust:"), u.dim(trust));
    }
    if let Some(category) = source.category.as_deref() {
        cli_println!("    {} {}", u.dim("category:"), u.dim(category));
    }
    if !source.payload_types.is_empty() {
        cli_println!(
            "    {} {}",
            u.dim("payload:"),
            u.dim(&source.payload_types.join(", "))
        );
    }
    let summary = pack
        .find_rule_by_id(&source.rule_id)
        .map(|rule| rule.description.trim().to_string())
        .filter(|desc| !desc.is_empty())
        .unwrap_or_else(|| "inferred entry-point parameter used as a taint seed.".to_string());
    if !summary.is_empty() {
        for line in u.wrapped_dim_prefixed_lines(
            "    summary: ",
            &format!("    {} ", u.dim("summary:")),
            "             ",
            &summary,
        ) {
            cli_println!("{line}");
        }
    }
}

/// Print the security-finding narrative for one finding. Framed as a
/// vulnerability report, not a raw rule dump: headline severity +
/// vulnerability class, a synthesised one-sentence summary of what's
/// happening, then labelled `SOURCE:` / `SANITIZER:` / `SINK:` blocks
/// that each read as short prose (what the input is, what the dangerous
/// operation is, why it's dangerous) plus the rule id, location, and
/// supporting taxonomy metadata (CWE, OWASP, category, packages,
/// frameworks). Goes above the taint-flow block so a reviewer sees
/// the finding *as a vulnerability* before reading the propagation.
fn render_finding_security_header(u: &Ui, idx: usize, combined: &CombinedFindingWithChain, pack: &Rulepack) {
    let f = &combined.finding;
    let sev = f
        .severity
        .map_or_else(|| "-".to_string(), |s| s.as_str().to_string());
    let sink_count = 1 + combined.additional_sinks.len();
    let source_count = 1 + combined.additional_sources.len();
    let vuln_class = if sink_count > 1 {
        "multiple-sinks"
    } else {
        f.tag.as_deref().unwrap_or("vulnerability")
    };
    cli_println!();
    cli_println!("{}", u.ruler('═', 70));
    // Headline: `FINDING 1 · command-injection · critical  S:<16-hex>`.
    cli_println!(
        "{} · {} · {}  {}",
        u.annotation(&format!("FINDING {idx}")),
        u.name(vuln_class),
        severity_cell(u, &sev),
        u.dim(&f.finding_id),
    );
    // Status line — see security-spec.mdx "Sanitized Does Not Mean
    // Safe". Always rendered: the reviewer must know which bucket
    // each finding is in.
    let status_label = match f.status {
        FindingStatus::Unsanitized => u.warn("status: unsanitized"),
        FindingStatus::Sanitized => u.dim("status: sanitized · review for bypass"),
        FindingStatus::WrongContext => {
            u.warn("status: WRONG-CONTEXT — sanitizer fired but does not cover this sink")
        }
    };
    cli_println!("  {}", status_label);
    if let Some(flow_id) = f.representative_flow_id.as_deref() {
        let group_id = f.group_id.as_deref().unwrap_or("-");
        cli_println!(
            "  {} {}  ·  {} {}",
            u.dim("flow:"),
            u.dim(flow_id),
            u.dim("group:"),
            u.dim(group_id),
        );
    } else if let Some(group_id) = f.group_id.as_deref() {
        cli_println!("  {} {}", u.dim("group:"), u.dim(group_id));
    }
    if sink_count > 1 {
        cli_println!("  {}      {}", u.dim("sinks:"), u.dim(&sink_count.to_string()));
    }
    if source_count > 1 {
        cli_println!("  {}    {}", u.dim("sources:"), u.dim(&source_count.to_string()));
    }

    // Taxonomy line(s). Keep compact — one field per line only when
    // non-empty, with a dim label so the body reads like a report.
    if !f.cwe.is_empty() {
        cli_println!("  {}        {}", u.dim("cwe:"), u.dim(&f.cwe.join(", ")));
    }
    if !f.owasp.is_empty() {
        cli_println!("  {}      {}", u.dim("owasp:"), u.dim(&f.owasp.join(", ")));
    }
    let packages = combined_sink_metadata(combined, pack, |r| &r.packages);
    if !packages.is_empty() {
        for line in u.wrapped_dim_prefixed_lines(
            "  packages: ",
            &format!("  {} ", u.dim("packages:")),
            "            ",
            &packages.join(", "),
        ) {
            cli_println!("{line}");
        }
    }
    let frameworks = combined_sink_metadata(combined, pack, |r| &r.frameworks);
    if !frameworks.is_empty() {
        for line in u.wrapped_dim_prefixed_lines(
            "  frameworks: ",
            &format!("  {} ", u.dim("frameworks:")),
            "              ",
            &frameworks.join(", "),
        ) {
            cli_println!("{line}");
        }
    }
    cli_println!();

    // One-sentence synthesised summary. Pulls the source-rule
    // description (the "what the input is" half) and the sink-rule
    // description (the "why it's dangerous" half) from the YAML and
    // stitches them with "→". A plain-English overview before the
    // per-side evidence blocks below.
    if let Some(summary) = synth_summary(combined, pack) {
        for line in u.wrapped_dim_prefixed_lines(
            "  summary: ",
            &format!("  {} ", u.dim("summary:")),
            "           ",
            &summary,
        ) {
            cli_println!("{line}");
        }
        cli_println!();
    }

    render_finding_side(u, FindingSide::Source, &f.source, pack);
    for source in &combined.additional_sources {
        render_finding_side(u, FindingSide::Source, source, pack);
    }
    for transform in &f.taint_transforms_seen {
        render_finding_side(u, FindingSide::TaintTransform, transform, pack);
    }
    for s in &f.sanitizers_seen {
        render_finding_side(u, FindingSide::Sanitizer, s, pack);
    }
    if f.sanitizers_seen.is_empty() {
        cli_println!();
        cli_println!(
            "  {}  {}",
            u.kind("SANITIZER:"),
            u.warn("none observed on this call path"),
        );
    }
    render_finding_side(u, FindingSide::Sink, &f.sink, pack);
    for sink in &combined.additional_sinks {
        render_finding_side(u, FindingSide::Sink, sink, pack);
    }
    cli_println!("{}", u.ruler('─', 70));
}

fn combined_sink_metadata<F>(combined: &CombinedFindingWithChain, pack: &Rulepack, field: F) -> Vec<String>
where
    F: Fn(&Rule) -> &Vec<String>,
{
    let mut out = Vec::new();
    for sink in all_sink_matches(combined) {
        if let Some(rule) = pack.find_rule_by_id(&sink.rule_id) {
            for value in field(rule) {
                if !out.contains(value) {
                    out.push(value.clone());
                }
            }
        }
    }
    out
}

fn all_sink_matches(combined: &CombinedFindingWithChain) -> Vec<FindingMatch> {
    let mut sinks = Vec::with_capacity(1 + combined.additional_sinks.len());
    sinks.push(combined.finding.sink.clone());
    sinks.extend(combined.additional_sinks.iter().cloned());
    sinks
}

#[derive(Copy, Clone)]
enum FindingSide {
    Source,
    TaintTransform,
    Sanitizer,
    Sink,
}

impl FindingSide {
    fn label(self) -> &'static str {
        match self {
            Self::Source => "SOURCE:",
            Self::TaintTransform => "TAINT TRANSFORM:",
            Self::Sanitizer => "SANITIZER:",
            Self::Sink => "SINK:",
        }
    }
    /// Narrative prefix for the rule description — the half-sentence
    /// that makes each side read as explanation rather than a rule
    /// dump. The rule's own description continues the sentence.
    fn narrative_prefix(self) -> &'static str {
        match self {
            Self::Source => "untrusted input —",
            Self::TaintTransform => "taint preserved by —",
            Self::Sanitizer => "sanitized via —",
            Self::Sink => "dangerous operation —",
        }
    }
}

/// Emit one side of the finding (source / taint transform / sanitizer / sink) as a
/// short prose block: label, rule id, the "what this is" narrative
/// line (rule description prefixed with a side-specific framing),
/// file:line:col location with enclosing function, and a compact
/// chip trailer for supporting taxonomy that didn't fit the headline
/// (trust, tag, category, CWE, packages, frameworks). Matches the
/// framing of a bug report more than a rule dump.
fn render_finding_side(u: &Ui, side: FindingSide, m: &FindingMatch, pack: &Rulepack) {
    let rule = pack.find_rule_by_id(&m.rule_id);
    cli_println!();
    cli_println!("  {}  {}", u.kind(side.label()), u.name(&m.rule_id),);
    if let Some(r) = rule {
        let desc = r.description.trim();
        if !desc.is_empty() {
            let prefix = format!("    {} ", side.narrative_prefix());
            for line in u.wrapped_dim_prefixed_lines(
                &prefix,
                &format!("    {} ", u.dim(side.narrative_prefix())),
                &" ".repeat(prefix.len()),
                desc,
            ) {
                cli_println!("{line}");
            }
        }
    }
    let loc = format!("{}:{}:{}", short_file(&m.file), m.line, m.column);
    let in_fn = m
        .enclosing_fn
        .as_deref()
        .map_or_else(|| "<module>".to_string(), |f| format!("in {f}"));
    cli_println!("    {} {}  {}", u.dim("at"), u.path(&loc), u.dim(&in_fn),);
    // Sink-side: surface the per-arg taint evidence so the consumer
    // (LLM or human) can tell "URL is tainted" from "body is tainted"
    // without re-parsing.
    if matches!(side, FindingSide::Sink) && !m.tainted_args.is_empty() {
        let args_text = m
            .tainted_args
            .iter()
            .map(|a| {
                let pos = if a.index == usize::MAX {
                    "receiver".to_string()
                } else {
                    format!("[{}]", a.index)
                };
                format!("{} {}", pos, a.value_text)
            })
            .collect::<Vec<_>>()
            .join(", ");
        for line in u.wrapped_dim_prefixed_lines(
            "    tainted args: ",
            &format!("    {} ", u.dim("tainted args:")),
            "                  ",
            &args_text,
        ) {
            cli_println!("{line}");
        }
    }
    // Supporting taxonomy chips — only fields not already in the
    // finding headline above, so we don't repeat severity / cwe /
    // owasp / packages / frameworks for the sink side.
    let mut chips: Vec<String> = Vec::new();
    if matches!(side, FindingSide::Source) {
        if let Some(trust) = m.trust.as_deref() {
            chips.push(meta_chip(u, "trust", u.dim(trust)));
        }
    }
    if let Some(tag) = m.tag.as_deref() {
        chips.push(meta_chip(u, "tag", u.dim(tag)));
    }
    if let Some(cat) = m.category.as_deref() {
        chips.push(meta_chip(u, "category", u.dim(cat)));
    }
    // Sink-side only: sink severity (source severity is irrelevant).
    // The finding's severity (from the sink) already appears in the
    // headline, so skip it here.
    if matches!(side, FindingSide::Sanitizer | FindingSide::TaintTransform) {
        if let Some(r) = rule {
            if !r.packages.is_empty() {
                chips.push(meta_chip(u, "packages", u.dim(&r.packages.join(", "))));
            }
        }
    }
    if !chips.is_empty() {
        cli_println!("    {}  {}", u.dim("—"), chips.join(" · "));
    }
}

/// One-sentence synthesised summary of the finding. Joins the source
/// rule's description (the "where the input comes from" half) with
/// the sink rule's description (the "what goes wrong" half) using
/// "→", so the line reads as a cause→effect narrative. Returns
/// `None` when either description is empty so we can skip the line.
fn synth_summary(combined: &CombinedFindingWithChain, pack: &Rulepack) -> Option<String> {
    let f = &combined.finding;
    let src = pack.find_rule_by_id(&f.source.rule_id)?;
    let src_desc = src.description.trim();
    if src_desc.is_empty() {
        return None;
    }
    let mut sink_descs = Vec::new();
    for sink in all_sink_matches(combined) {
        let Some(rule) = pack.find_rule_by_id(&sink.rule_id) else {
            continue;
        };
        let desc = rule.description.trim();
        if !desc.is_empty() && !sink_descs.contains(&desc) {
            sink_descs.push(desc);
        }
    }
    if sink_descs.is_empty() {
        return None;
    }
    // Strip trailing period so the "→" join reads as one sentence.
    let src_clean = src_desc.trim_end_matches('.');
    let sink_summary = if sink_descs.len() == 1 {
        sink_descs[0].trim_end_matches('.').to_string()
    } else {
        let joined = sink_descs
            .iter()
            .take(3)
            .map(|s| s.trim_end_matches('.'))
            .collect::<Vec<_>>()
            .join("; ");
        if sink_descs.len() > 3 {
            format!("{joined}; +{} more sink(s)", sink_descs.len() - 3)
        } else {
            joined
        }
    };
    Some(format!("{src_clean} → {sink_summary}."))
}

/// Compact render when the finding has no cross-function FuncId
/// chain — a SOURCE / SANITIZER / SINK block list with the
/// syntax-highlighted code line at each site, no source bodies.
/// Same visual shape as the per-side blocks in the taint-analysis
/// render, so same-file findings still read coherently without
/// implying approximate analysis.
fn render_finding_block_compact(u: &Ui, combined: &CombinedFindingWithChain, pack: &Rulepack) {
    let f = &combined.finding;
    cli_println!();
    // The full per-function body render (`render_flow_with_cached_call_spans`)
    // couldn't resolve every hop — e.g. an inheritance `super` hop that
    // the canonical chain collapses (`run → run → execute` rendered as
    // `run → execute`, leaving no direct `run → execute` call edge), or a
    // synthesized data-holder accessor with no source span of its own.
    // When a cross-function chain still EXISTS in the propagation data,
    // show it from `taint_path` / `chain_display` rather than mislabeling
    // the finding as same-file (the flow IS cross-function — only the
    // body-level render degraded).
    let distinct_fns = f
        .chain_display
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if !f.taint_path.is_empty() || distinct_fns > 1 {
        if !f.chain_display.is_empty() {
            cli_println!("{}  {}", u.kind("CHAIN"), u.dim(&f.chain_display.join(" → ")));
        }
        for step in &f.taint_path {
            let loc = format!("{}:{}", short_file(&step.file), step.line);
            let args: Vec<&str> = step.tainted_args.iter().map(|a| a.value_text.as_str()).collect();
            let arg_note = if args.is_empty() {
                String::new()
            } else {
                format!("  tainted: {}", args.join(", "))
            };
            cli_println!(
                "    {} → {}  {}{}",
                u.name(&step.caller),
                u.name(&step.callee),
                u.path(&loc),
                u.dim(&arg_note),
            );
        }
    } else {
        cli_println!("{}", u.dim("(same-file evidence — no cross-function chain)"));
    }
    render_site_code(u, "SOURCE", &f.source, pack);
    for source in &combined.additional_sources {
        render_site_code(u, "SOURCE", source, pack);
    }
    for transform in &f.taint_transforms_seen {
        render_site_code(u, "TAINT TRANSFORM", transform, pack);
    }
    for s in &f.sanitizers_seen {
        render_site_code(u, "SANITIZER", s, pack);
    }
    render_site_code(u, "SINK", &f.sink, pack);
    for sink in &combined.additional_sinks {
        render_site_code(u, "SINK", sink, pack);
    }
}

fn render_site_code(u: &Ui, label: &str, m: &FindingMatch, pack: &Rulepack) {
    cli_println!();
    cli_println!("{}  {}", u.kind(&format!("[{label}]")), u.name(&m.rule_id),);
    let loc = format!("{}:{}:{}", short_file(&m.file), m.line, m.column);
    cli_println!(
        "    {}  {}",
        u.path(&loc),
        u.dim(
            &m.enclosing_fn
                .as_deref()
                .map_or_else(|| "<module>".to_string(), |f| format!("in {f}"))
        ),
    );
    if !m.text.trim().is_empty() {
        cli_println!("    {}", u.snippet(m.text.trim(), extension_for(&m.file)));
    }
    if let Some(r) = pack.find_rule_by_id(&m.rule_id) {
        let desc = r.description.trim();
        if !desc.is_empty() {
            for line in u.wrapped_dim_prefixed_lines("    ", "    ", "    ", desc) {
                cli_println!("{line}");
            }
        }
    }
}

fn function_costs_for_paths<I>(
    ws: &bonsai_sdk::Workspace,
    funcs: I,
    full_body_cost: bool,
) -> ahash::AHashMap<FuncId, u64>
where
    I: IntoIterator<Item = FuncId>,
{
    let mut out = ahash::AHashMap::new();
    let global = ws.compiler_linkage_index();
    for func in funcs {
        if out.contains_key(&func) {
            continue;
        }
        let cost = global
            .decl_of(bonsai_common::SymbolId::new(func.raw()))
            .map_or(512, |decl| {
                let span = decl.body_span.unwrap_or(decl.span);
                let path_len = ws
                    .vfs()
                    .path(span.file)
                    .map(|path| path.display().to_string().len() as u64)
                    .unwrap_or(32);
                let signature_len =
                    (decl.name.len() + decl.params.iter().map(|p| p.len() + 2).sum::<usize>()) as u64;
                let (body_bytes_raw, line_count_raw) = ws
                    .vfs()
                    .snapshot(span.file)
                    .ok()
                    .and_then(|snapshot| {
                        let text = snapshot.text.as_bytes();
                        let start = usize::try_from(span.start).ok()?;
                        let end =
                            usize::try_from(span.end.min(u64::try_from(text.len()).unwrap_or(u64::MAX)))
                                .ok()?;
                        if start < end && end <= text.len() {
                            let bytes = &text[start..end];
                            #[allow(clippy::naive_bytecount)]
                            // small token spans; bytecount crate not worth the dep
                            let lines = bytes.iter().filter(|b| **b == b'\n').count() as u64 + 1;
                            Some((bytes.len() as u64, lines))
                        } else {
                            None
                        }
                    })
                    .unwrap_or((span.len(), 1));
                let (body_bytes, line_count) = if full_body_cost {
                    (body_bytes_raw, line_count_raw)
                } else {
                    (body_bytes_raw.min(12_000), line_count_raw.min(240))
                };

                // Mirrors the text flow renderer: module/def chrome,
                // line-number gutters, annotations, and syntax/snippet
                // overhead on every line. Intentionally conservative;
                // overestimating creates smaller pages, while
                // underestimating can blow past --context by megabytes.
                let line_overhead = if full_body_cost { 96 } else { 48 };
                let safety_num = if full_body_cost { 3 } else { 1 };
                let safety_den = if full_body_cost { 2 } else { 1 };
                (path_len + signature_len + body_bytes + line_count * line_overhead + 256)
                    .saturating_mul(safety_num)
                    / safety_den
            });
        out.insert(func, cost);
    }
    out
}

fn match_text_cost(m: &FindingMatch, pack: &Rulepack) -> u64 {
    let rule_desc = pack
        .find_rule_by_id(&m.rule_id)
        .map(|rule| rule.description.len() as u64)
        .unwrap_or(0);
    (m.rule_id.len()
        + m.file.len()
        + m.text.len()
        + m.enclosing_fn.as_deref().map_or(0, str::len)
        + m.tag.as_deref().map_or(0, str::len)
        + m.category.as_deref().map_or(0, str::len)
        + m.trust.as_deref().map_or(0, str::len)
        + m.payload_types.iter().map(|p| p.len() + 2).sum::<usize>()) as u64
        + rule_desc
        + 384
}

fn source_analysis_text_cost_bytes(
    candidate: &CombinedSourceAnalysisCandidate,
    pack: &Rulepack,
    function_costs: &ahash::AHashMap<FuncId, u64>,
) -> u64 {
    1200 + match_text_cost(&candidate.source, pack)
        + candidate
            .additional_sources
            .iter()
            .map(|m| match_text_cost(m, pack))
            .sum::<u64>()
        + candidate
            .chain_names
            .iter()
            .map(|hop| hop.len() as u64 + 8)
            .sum::<u64>()
        + candidate
            .path
            .iter()
            .map(|func| function_costs.get(func).copied().unwrap_or(512))
            .sum::<u64>()
}

// Note: SDK severity parsing is case-insensitive. The previous
// CLI-local copy was case-sensitive and rejected `--severity HIGH`
// etc.; routing through the SDK removes the parity drift.

/// Parse an `Option<String>` severity flag, erroring if the caller
/// passed a value that isn't one of the recognised levels. The plain
/// SDK parser returns `None` for invalid values; CLI paths wrap it in
/// this helper to distinguish unset from a typo like `--severity hihg`.
fn parse_severity_flag(flag: Option<&str>) -> Result<Option<Severity>> {
    match flag {
        None => Ok(None),
        Some(s) => parse_severity(s).map(Some).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid --severity value '{s}' (expected one of: info, low, medium, high, critical)"
            )
        }),
    }
}

fn precision_from_finding_label(label: &str) -> Precision {
    match label {
        "exact" => Precision::Exact,
        "narrowed" => Precision::Narrowed,
        "over-approximate" | "over_approximate" => Precision::OverApproximate,
        "unknown" => Precision::Unknown,
        _ => Precision::Unknown,
    }
}

fn filter_signature(pairs: &[(&str, &str)]) -> u64 {
    paging::hash_filters(pairs)
}

fn effective_limit(limit: usize, cfg: &paging::PagingConfig) -> usize {
    crate::commands::browse::effective_limit(limit, cfg)
}

fn trust_str(t: TrustClass) -> &'static str {
    match t {
        TrustClass::Remote => "remote",
        TrustClass::Local => "local",
        TrustClass::Service => "service",
        TrustClass::Ipc => "ipc",
        TrustClass::Database => "database",
        TrustClass::Library => "library",
        TrustClass::Config => "config",
        TrustClass::Physical => "physical",
    }
}

fn severity_cell(u: &Ui, sev: &str) -> String {
    match sev {
        "critical" | "high" | "medium" => u.warn(sev),
        _ => u.dim(sev),
    }
}

fn meta_chip(u: &Ui, label: &str, value: String) -> String {
    format!("{} {}", u.dim(label), value)
}

// ---- match-table renderer (sources + sinks) ----
/// Render `security sources` / `security sinks` matches as one inspect-
/// style block per match — rule id + metadata chips, file:line:col +
/// enclosing fn, syntax-highlighted source line, rule description.
/// Replaces the old dense table so triaging a hit doesn't require
/// opening the YAML. JSON output keeps every field (including the new
/// description / cwe / owasp / frameworks / packages chips) so tooling
/// gets the same context.
#[allow(clippy::too_many_arguments)] // Shared renderer needs both workspace context and paging/cache keys.
fn render_match_table(
    workspace: &Path,
    label: &str,
    matches: &[RuleMatch],
    pack: &Rulepack,
    ws: &bonsai_sdk::Workspace,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
    show_severity: bool,
    filters_hash: u64,
) -> Result<()> {
    let cost = |m: &RuleMatch| {
        (m.rule_id.len()
            + m.language.len()
            + m.file.len()
            + m.match_text.len().min(120)
            + m.enclosing_fn.as_deref().map_or(0, str::len)
            + 160) as u64
            + paging::TABLE_ROW_CHROME_BYTES // + allowance for description row
    };

    match format {
        BrowseFormat::Json => {
            let rows = security_match_rows(pack, matches);
            let cost_row = |_: &SecurityMatchRow| 512u64;
            let command = format!("security/{label}");
            page_cache::emit_paged_text(
                workspace,
                &rows,
                &paging_cfg,
                &command,
                filters_hash,
                cost_row,
                |paged, info, _cfg| {
                    let analysis_incomplete_reasons = paged_json_incomplete_reasons(&command, info);
                    let payload = serde_json::json!({
                        "analysis_complete": analysis_incomplete_reasons.is_empty(),
                        "analysis_incomplete_reasons": analysis_incomplete_reasons,
                        "page": page_info_to_json(info),
                        "rows": paged,
                    });
                    cli_println!("{}", serde_json::to_string_pretty(&payload)?);
                    Ok(())
                },
            )?;
        }
        BrowseFormat::Text => {
            let command = format!("security/{label}");
            page_cache::emit_paged_text(
                workspace,
                matches,
                &paging_cfg,
                &command,
                filters_hash,
                cost,
                |paged, info, cfg| {
                    let limit_eff = effective_limit(limit, cfg);
                    let truncated = if limit_eff != 0 && paged.len() > limit_eff {
                        Some(paged.len() - limit_eff)
                    } else {
                        None
                    };
                    let rows: Vec<RuleMatch> = if limit_eff == 0 {
                        paged.to_vec()
                    } else {
                        paged.iter().take(limit_eff).cloned().collect()
                    };
                    let u = ui();
                    let block_label: String = match label {
                        "sources" => "SOURCE".to_string(),
                        "sinks" => "SINK".to_string(),
                        "sanitizers" => "SANITIZER".to_string(),
                        other => other.to_ascii_uppercase(),
                    };
                    cli_println!(
                        "{}",
                        u.dim(&format!("security {label} — {} match(es)", matches.len()))
                    );
                    for (idx, m) in rows.iter().enumerate() {
                        render_standalone_match(u, &block_label, idx + 1, m, pack, ws, show_severity);
                    }
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, &format!("bonsai-ninja security <workspace> {label}"));
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

/// One source / sink match rendered as an inspect-style block. Shares
/// the visual shape of `render_match_row` (the per-side block inside a
/// finding) so `security sinks` and `security taint-analysis`'s SINK
/// sections read identically.
fn render_standalone_match(
    u: &Ui,
    label: &str,
    idx: usize,
    m: &RuleMatch,
    pack: &Rulepack,
    _ws: &bonsai_sdk::Workspace,
    show_severity: bool,
) {
    let rule = pack.find_rule_by_id(&m.rule_id);
    let mut chips: Vec<String> = Vec::new();
    if show_severity {
        let sev = rule.and_then(|r| r.severity.map(|s| s.as_str())).unwrap_or("-");
        chips.push(meta_chip(u, "severity", severity_cell(u, sev)));
    }
    if let Some(trust) = rule.and_then(|r| r.trust) {
        chips.push(meta_chip(u, "trust", u.dim(trust_str(trust))));
    }
    if let Some(cat) = rule.and_then(|r| r.category.as_deref()) {
        chips.push(meta_chip(u, "category", u.dim(cat)));
    }
    if let Some(tag) = rule.and_then(|r| r.tag.as_deref()) {
        chips.push(meta_chip(u, "tag", u.dim(tag)));
    }
    if let Some(r) = rule {
        if !r.cwe.is_empty() {
            chips.push(meta_chip(u, "cwe", u.dim(&r.cwe.join(", "))));
        }
        if !r.frameworks.is_empty() {
            chips.push(meta_chip(u, "frameworks", u.dim(&r.frameworks.join(", "))));
        }
        if !r.packages.is_empty() {
            chips.push(meta_chip(u, "packages", u.dim(&r.packages.join(", "))));
        }
    }
    cli_println!();
    cli_println!("{}  {}", u.kind(&format!("[{label} {idx}]")), u.name(&m.rule_id),);
    if !chips.is_empty() {
        for line in u.wrapped_dim_prefixed_lines(
            "    meta: ",
            &format!("    {} ", u.dim("meta:")),
            "          ",
            &chips.join(" · "),
        ) {
            cli_println!("{line}");
        }
    }
    let loc = format!("{}:{}:{}", short_file(&m.file), m.line, m.column);
    let in_fn = m
        .enclosing_fn
        .as_deref()
        .map_or_else(|| "<module>".to_string(), |f| format!("in {f}"));
    cli_println!(
        "    {}  {}   ({})",
        u.path(&loc),
        u.dim(&in_fn),
        u.dim(&m.language),
    );
    if !m.match_text.trim().is_empty() {
        cli_println!("    {}", u.snippet(m.match_text.trim(), extension_for(&m.file)));
    }
    if let Some(r) = rule {
        let desc = r.description.trim();
        if !desc.is_empty() {
            for line in u.wrapped_dim_prefixed_lines("    ", "    ", "    ", desc) {
                cli_println!("{line}");
            }
        }
    }
}

/// Render one `security deps` package as an inspect-style block.
/// Header with chips (severity / lang / tags / rule count / signals),
/// evidence files (up to five, with `+N more` trailer), and one dim
/// description line per unique rule that claimed the package — so
/// reviewers see exactly why the pack cares about it without
/// opening the YAML.
fn render_dep_block(u: &Ui, idx: usize, r: &DependencyRow, pack: &Rulepack) {
    let mut chips: Vec<String> = Vec::new();
    if let Some(sev) = r.severity {
        chips.push(meta_chip(u, "severity", severity_cell(u, sev.as_str())));
    }
    chips.push(meta_chip(u, "lang", u.dim(&r.language)));
    if !r.tags.is_empty() {
        chips.push(meta_chip(u, "tags", u.dim(&r.tags.join(", "))));
    }
    chips.push(meta_chip(u, "rules", u.dim(&r.rule_ids.len().to_string())));
    if !r.signals.is_empty() {
        let take: Vec<&str> = r.signals.iter().take(4).map(|s| s.as_str()).collect();
        let mut joined = take.join(", ");
        if r.signals.len() > 4 {
            joined.push_str(&format!(", +{} more", r.signals.len() - 4));
        }
        chips.push(meta_chip(u, "signals", u.dim(&joined)));
    }
    cli_println!();
    cli_println!("{}  {}", u.kind(&format!("[PACKAGE {idx}]")), u.name(&r.key),);
    for line in u.wrapped_dim_prefixed_lines(
        "    meta: ",
        &format!("    {} ", u.dim("meta:")),
        "          ",
        &chips.join(" · "),
    ) {
        cli_println!("{line}");
    }

    let shown: Vec<&String> = r.evidence_files.iter().take(5).collect();
    for file in &shown {
        cli_println!("    {}", u.path(&short_file(file)));
    }
    if r.evidence_files.len() > shown.len() {
        cli_println!(
            "    {}",
            u.dim(&format!("… +{} more", r.evidence_files.len() - shown.len()))
        );
    }

    let mut seen_desc: ahash::AHashSet<String> = ahash::AHashSet::new();
    for rid in &r.rule_ids {
        if let Some(rule) = pack.find_rule_by_id(rid) {
            let desc = rule.description.trim();
            if !desc.is_empty() && seen_desc.insert(desc.to_string()) {
                for line in u.wrapped_bullet_lines("·", desc) {
                    cli_println!("{line}");
                }
            }
        }
    }
}

fn dep_block_cost_bytes(r: &DependencyRow, pack: &Rulepack) -> u64 {
    let chip_bytes = r.language.len()
        + r.key.len()
        + r.tags.iter().map(|s| s.len() + 2).sum::<usize>()
        + r.signals.iter().take(4).map(|s| s.len() + 2).sum::<usize>()
        + r.rule_ids.len().to_string().len()
        + 96;
    let evidence_bytes = r
        .evidence_files
        .iter()
        .take(5)
        .map(|file| short_file(file).len() + 8)
        .sum::<usize>()
        + if r.evidence_files.len() > 5 { 32 } else { 0 };
    let mut seen_desc: ahash::AHashSet<&str> = ahash::AHashSet::new();
    let description_bytes = r
        .rule_ids
        .iter()
        .filter_map(|rid| pack.find_rule_by_id(rid))
        .map(|rule| rule.description.trim())
        .filter(|desc| !desc.is_empty() && seen_desc.insert(*desc))
        // Bullet rendering wraps descriptions and adds indentation on
        // each line. Description bytes dominate the block; a fixed
        // per-description allowance keeps pages under context without
        // wasting most of the requested budget.
        .map(|desc| desc.len().saturating_add(64))
        .sum::<usize>();
    (chip_bytes + evidence_bytes + description_bytes) as u64 + paging::TABLE_ROW_CHROME_BYTES
}

// ---- pack — rulepack inspector / auditor ----
// Mode flags (audit / tree / validate / taint_replay) mirror the `pack`
// subcommand's CLI flags one-to-one; grouping them into a struct would
// just shift the boolean surface without improving the call site.
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn cmd_pack(
    workspace: &Path,
    pack: &Rulepack,
    lang: Option<String>,
    category: Option<String>,
    kind: Option<String>,
    severity: Option<String>,
    audit: bool,
    tree: bool,
    validate: bool,
    taint_replay: bool,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let paging_cfg = paging_with_row_limit(paging_cfg, limit);
    let kind_filter = match kind.as_deref() {
        Some("source") => Some(RuleKind::Source),
        Some("sink") => Some(RuleKind::Sink),
        Some("sanitizer") => Some(RuleKind::Sanitizer),
        Some("typing") => Some(RuleKind::Typing),
        Some(other) => {
            anyhow::bail!("unknown --kind `{other}` (expected source|sink|sanitizer|typing)")
        }
        None => None,
    };
    let sev_floor = parse_severity_flag(severity.as_deref())?;

    let pack_facade = bonsai_sdk::SecurityPack::new(pack);
    let pack_options = PackInventoryOptions {
        lang: lang.clone(),
        category: category.clone(),
        kind: kind_filter,
        severity: sev_floor,
        taint_replay_examples: taint_replay,
    };
    let base_filters_hash = filter_signature(&[
        ("kind", "pack"),
        ("lang", lang.as_deref().unwrap_or("")),
        ("category", category.as_deref().unwrap_or("")),
        ("rkind", kind.as_deref().unwrap_or("")),
        ("severity", severity.as_deref().unwrap_or("")),
        ("taint_replay", if taint_replay { "1" } else { "0" }),
    ]);

    if audit {
        return render_audit(
            workspace,
            pack,
            lang.as_deref(),
            &paging_cfg,
            base_filters_hash,
            format,
        );
    }
    if validate {
        return render_pack_validation(
            workspace,
            pack,
            &pack_options,
            &paging_cfg,
            base_filters_hash,
            format,
        );
    }
    if tree {
        // Use the SDK's `select_pack_rules` to filter+sort once
        // instead of an O(rows × pack.all_rules) membership scan.
        // Don't run `inventory()` first — the tree branch never
        // touches `rows`.
        let rules = pack_facade.select_rules(&pack_options);
        return render_tree(
            workspace,
            pack,
            &rules,
            pack_options,
            &paging_cfg,
            base_filters_hash,
            format,
        );
    }
    // Single source of truth for filter/sort on the non-tree
    // branch: the SDK's `inventory()` filters by
    // lang/kind/severity/category and sorts by
    // `(lang, kind, family, id)`. Both text and JSON render paths
    // consume the same `Vec<PackRuleRow>` so they can never drift
    // on filter semantics.
    let rows = pack_facade.inventory(pack_options.clone())?;

    let filters_hash = base_filters_hash;

    let cost_row = |r: &PackRuleRow| {
        (r.rule_id.len() + r.language.len() + r.tag.as_deref().map_or(0, str::len) + r.description.len() + 32)
            as u64
            + paging::TABLE_ROW_CHROME_BYTES
    };
    match format {
        BrowseFormat::Json => {
            page_cache::emit_paged_text(
                workspace,
                &rows,
                &paging_cfg,
                "security/pack",
                filters_hash,
                cost_row,
                |paged, info, _cfg| {
                    let analysis_incomplete_reasons = paged_json_incomplete_reasons("security/pack", info);
                    let payload = serde_json::json!({
                        "analysis_complete": analysis_incomplete_reasons.is_empty(),
                        "analysis_incomplete_reasons": analysis_incomplete_reasons,
                        "page": page_info_to_json(info),
                        "rows": paged,
                    });
                    cli_println!("{}", serde_json::to_string_pretty(&payload)?);
                    Ok(())
                },
            )?;
        }
        BrowseFormat::Text => {
            let row_count = rows.len();
            page_cache::emit_paged_text(
                workspace,
                &rows,
                &paging_cfg,
                "security/pack",
                filters_hash,
                cost_row,
                |paged, info, cfg| {
                    let limit_eff = effective_limit(limit, cfg);
                    let truncated = if limit_eff != 0 && paged.len() > limit_eff {
                        Some(paged.len() - limit_eff)
                    } else {
                        None
                    };
                    let display_rows: Vec<&PackRuleRow> = if limit_eff == 0 {
                        paged.iter().collect()
                    } else {
                        paged.iter().take(limit_eff).collect()
                    };
                    let u = ui();
                    cli_println!("{}", u.dim(&format!("security pack — {row_count} rule(s)")));
                    for (idx, r) in display_rows.iter().enumerate() {
                        render_pack_rule_block(u, idx + 1, r);
                    }
                    render_truncation_notice(display_rows.len(), truncated);
                    render_paging_footer(info, "bonsai-ninja security <ws> pack");
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

fn render_pack_rule_block(u: &Ui, idx: usize, r: &PackRuleRow) {
    let sev = r.severity.as_deref().unwrap_or("-");
    let state = if r.enabled { "enabled" } else { "disabled" };
    let mut chips = vec![
        meta_chip(u, "lang", u.dim(&r.language)),
        meta_chip(u, "kind", u.kind(&r.kind)),
        meta_chip(u, "family", u.kind(&r.family)),
        meta_chip(u, "severity", severity_cell(u, sev)),
        meta_chip(u, "state", u.dim(state)),
    ];
    if let Some(tag) = r.tag.as_deref().filter(|tag| !tag.is_empty()) {
        chips.push(meta_chip(u, "tag", u.dim(tag)));
    }

    cli_println!();
    cli_println!("{}  {}", u.kind(&format!("[RULE {idx}]")), u.name(&r.rule_id));
    for line in u.wrapped_dim_prefixed_lines(
        "    meta: ",
        &format!("    {} ", u.dim("meta:")),
        "          ",
        &chips.join(" · "),
    ) {
        cli_println!("{line}");
    }
    if !r.packages.is_empty() {
        for line in u.wrapped_dim_prefixed_lines(
            "    packages: ",
            &format!("    {} ", u.dim("packages:")),
            "              ",
            &r.packages.join(", "),
        ) {
            cli_println!("{line}");
        }
    }
    if !r.frameworks.is_empty() {
        for line in u.wrapped_dim_prefixed_lines(
            "    frameworks: ",
            &format!("    {} ", u.dim("frameworks:")),
            "                ",
            &r.frameworks.join(", "),
        ) {
            cli_println!("{line}");
        }
    }
    if !r.description.trim().is_empty() {
        for line in u.wrapped_dim_prefixed_lines(
            "    description: ",
            &format!("    {} ", u.dim("description:")),
            "                 ",
            r.description.trim(),
        ) {
            cli_println!("{line}");
        }
    }
}

fn render_pack_validation(
    workspace: &Path,
    pack: &Rulepack,
    options: &PackInventoryOptions,
    paging_cfg: &paging::PagingConfig,
    filters_hash: u64,
    format: BrowseFormat,
) -> Result<()> {
    let report = bonsai_sdk::SecurityPack::new(pack).validate(options.clone())?;
    match format {
        BrowseFormat::Json => {
            emit_json_value_paged_cached(
                workspace,
                &report,
                paging_cfg,
                "security/pack/validate",
                filters_hash,
            )?;
        }
        BrowseFormat::Text => {
            let u = ui();
            let status = if report.valid {
                u.name("valid")
            } else {
                u.warn("invalid")
            };
            cli_println!("{} {}", u.label("security pack validation"), status);
            let summary = format!(
                "{} rule(s), {} enabled, {} disabled, {} waiting on re-enable work, {} example(s) on enabled rules / {} total, {} error(s), {} warning(s)",
                report.rule_count,
                report.enabled_rule_count,
                report.disabled_rule_count,
                report.disabled_waiting_reenable_count,
                report.enabled_example_count,
                report.example_count,
                report.errors,
                report.warnings
            );
            for line in u.wrapped_dim_prefixed_lines("  ", "  ", "  ", &summary) {
                cli_println!("{line}");
            }
            if !report.disabled_reason_counts.is_empty() {
                let counts = report
                    .disabled_reason_counts
                    .iter()
                    .map(|(code, count)| format!("{code}: {count}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                for line in u.wrapped_dim_prefixed_lines(
                    "disabled reasons — ",
                    &u.dim("disabled reasons — "),
                    "                   ",
                    &counts,
                ) {
                    cli_println!("{line}");
                }
            }
            if !report.issues.is_empty() {
                let mut t = u.table(&["level", "code", "rule", "path", "message"]);
                for issue in &report.issues {
                    let level = u.warn(issue.level);
                    t.add_row(vec![
                        Cell::new(level),
                        Cell::new(issue.code),
                        Cell::new(issue.rule_id.as_deref().unwrap_or("-")),
                        Cell::new(issue.path.as_deref().unwrap_or("-")),
                        Cell::new(&issue.message),
                    ]);
                }
                cli_println!("{t}");
            }
        }
    }
    if report.valid {
        Ok(())
    } else {
        anyhow::bail!("rulepack validation failed with {} error(s)", report.errors)
    }
}

fn render_audit(
    workspace: &Path,
    pack: &Rulepack,
    lang_filter: Option<&str>,
    paging_cfg: &paging::PagingConfig,
    filters_hash: u64,
    format: BrowseFormat,
) -> Result<()> {
    // Single source of truth: the SDK's `pack_audit` builds the
    // per-(lang, family) matrix and applies the canonical
    // family-normalisation. CLI text rendering walks the same
    // report so JSON and text never disagree.
    let report = bonsai_sdk::SecurityPack::new(pack).audit(lang_filter)?;

    if matches!(format, BrowseFormat::Json) {
        emit_json_value_paged_cached(
            workspace,
            &report,
            paging_cfg,
            "security/pack/audit",
            filters_hash,
        )?;
        return Ok(());
    }

    // Text rendering: per-lang matrix with gaps highlighted.
    //
    // Short column abbreviations keep the matrix readable on an 80-
    // to 140-col terminal. We print a legend beneath so the codes
    // are still self-documenting. We also disable comfy-table's
    // Dynamic arrangement for this table specifically — with 20+
    // columns the dynamic arranger will char-wrap column headers
    // inside each cell (e.g. `crypto` becomes `cryp\nto`), which
    // destroys readability. Disabled gives each column its natural
    // width; the user can pipe to `less -S` if their terminal is
    // narrower than the resulting total.
    let u = ui();
    let mut headers: Vec<&str> = vec!["lang", "src", "san"];
    for fam in &report.canonical_sink_families {
        headers.push(family_short_label(&report, fam));
    }
    headers.push("gaps");
    let mut t = u.table(&headers);
    t.set_content_arrangement(comfy_table::ContentArrangement::Disabled);
    for lang in &report.languages {
        let mut row: Vec<Cell> = vec![
            Cell::new(u.name(&lang.language)),
            Cell::new(count_cell(u, lang.sources.enabled, 5)),
            Cell::new(count_cell(u, lang.sanitizers.enabled, 5)),
        ];
        let mut gaps: Vec<&str> = Vec::new();
        for fam in &report.canonical_sink_families {
            let entry = lang.sinks.get(fam);
            let not_applicable = entry.is_some_and(|e| e.not_applicable);
            if not_applicable {
                row.push(Cell::new(u.dim("n/a")));
                continue;
            }
            let enabled = entry.map_or(0, |e| e.enabled);
            row.push(Cell::new(count_cell(u, enabled, 3)));
            if enabled == 0 {
                gaps.push(fam.as_str());
            }
        }
        let gap_str = if gaps.is_empty() {
            "-".to_string()
        } else {
            // Short form in the gaps cell too so it doesn't force the
            // row to balloon past the terminal width.
            let shorts: Vec<&str> = gaps.iter().map(|f| family_short_label(&report, f)).collect();
            shorts.join(",")
        };
        row.push(Cell::new(u.warn(&gap_str)));
        t.add_row(row);
    }
    cli_println!("{t}");
    cli_println!(
        "{}",
        u.dim("audit: counts are enabled-only.  gaps lists sink families with 0 enabled rules.")
    );
    let descriptions = report
        .languages
        .iter()
        .flat_map(|language| {
            language
                .sinks
                .iter()
                .filter(|(_, count)| count.not_applicable)
                .map(|(family, _)| format!("{}/{family}", language.language))
        })
        .collect::<Vec<_>>();
    if !descriptions.is_empty() {
        cli_println!(
            "{}",
            u.dim(&format!(
                "n/a (per-cell) = family intentionally not applicable for that language ({})",
                descriptions.join(", ")
            ))
        );
    }
    cli_println!(
        "{}",
        u.dim(&format!(
            "covered: {} language(s); canonical app/web sink families tracked: {}",
            report.languages.len(),
            report.canonical_sink_families.len()
        ))
    );
    // Legend — print every abbreviation ↔ full family name so the
    // column headers are self-documenting.
    let legend = report
        .canonical_sink_families
        .iter()
        .map(|fam| {
            let short = family_short_label(&report, fam);
            if short == fam {
                fam.to_string()
            } else {
                format!("{short}={fam}")
            }
        })
        .collect::<Vec<_>>()
        .join("  ");
    for line in u.wrapped_dim_prefixed_lines("legend: ", &u.dim("legend: "), "        ", &legend) {
        cli_println!("{line}");
    }
    Ok(())
}

/// Compact column label for the audit matrix. Keep a stable 3-5 char
/// abbreviation for each long family name so 20-language × 17-family
/// tables don't force comfy-table into char-wrapping mode. Families
/// whose natural name is already short (`xss`, `jwt`, `tls`, …) are
/// returned verbatim.
fn family_short_label<'a>(report: &'a PackAuditReport, family: &'a str) -> &'a str {
    report
        .sink_family_short_labels
        .get(family)
        .map(String::as_str)
        .unwrap_or(family)
}

/// Pattern tree: rules grouped by (lang, kind, family) with headers
/// that mirror the actual YAML files on disk. Shows enabled/disabled counts per file
/// plus each rule's id, severity, and enabled state — a quick
/// file-level pack survey. Respects `--lang` / `--kind` /
/// `--category` / `--severity` via the already-filtered `rules` slice.
fn render_tree(
    workspace: &Path,
    pack: &Rulepack,
    rules: &[&Rule],
    _options: PackInventoryOptions,
    paging_cfg: &paging::PagingConfig,
    filters_hash: u64,
    format: BrowseFormat,
) -> Result<()> {
    if matches!(format, BrowseFormat::Json) {
        // Pass the prebuilt rule slice through `pack_tree_for_rules`
        // so we don't re-run the same filter+sort that produced
        // `rules` in the first place. The SDK helper that takes
        // `PackInventoryOptions` would internally re-derive the
        // same `rules` slice — wasted work.
        let report = bonsai_sdk::SecurityPack::new(pack).tree_for_rules(rules)?;
        emit_json_value_paged_cached(workspace, &report, paging_cfg, "security/pack/tree", filters_hash)?;
        return Ok(());
    }

    // Text rendering.
    let u = ui();
    use ahash::AHashMap;
    let mut grouped: AHashMap<String, AHashMap<&'static str, AHashMap<String, Vec<&Rule>>>> = AHashMap::new();
    for r in rules {
        grouped
            .entry(r.language.clone())
            .or_default()
            .entry(rule_kind_str(r.kind))
            .or_default()
            .entry(tree_file_rel(pack, r))
            .or_default()
            .push(r);
    }
    let mut langs: Vec<&String> = grouped.keys().collect();
    langs.sort();
    let mut total_rules = 0usize;
    for (i, l) in langs.iter().enumerate() {
        if i > 0 {
            cli_println!();
        }
        cli_println!("{}/", u.name(l));
        let kinds = &grouped[*l];
        // Emit sources, sinks, sanitizers in that order — matches the
        // on-disk directory convention.
        for kind in ["source", "sink", "sanitizer"] {
            let Some(files) = kinds.get(kind) else { continue };
            cli_println!("  {}s/", u.kind(kind));
            let mut file_names: Vec<&String> = files.keys().collect();
            file_names.sort();
            for file_name in file_names {
                let mut file_rules = files[file_name].clone();
                file_rules.sort_by(|a, b| a.id.cmp(&b.id));
                let enabled = file_rules.iter().filter(|r| r.enabled).count();
                let disabled = file_rules.len() - enabled;
                let header = if disabled == 0 {
                    format!("    {}  {} rule(s)", file_name, file_rules.len())
                } else {
                    format!(
                        "    {}  {} rule(s) ({} on, {} off)",
                        file_name,
                        file_rules.len(),
                        enabled,
                        disabled
                    )
                };
                cli_println!("{}", u.dim(&header));
                for r in file_rules {
                    let sev = r
                        .severity
                        .map_or_else(|| "-".to_string(), |s| s.as_str().to_string());
                    let on_marker = if r.enabled { u.name("on ") } else { u.warn("off") };
                    cli_println!(
                        "      {}  [{}]  {}",
                        u.name(&r.id),
                        severity_cell(u, &sev),
                        on_marker
                    );
                    total_rules += 1;
                }
            }
        }
    }
    cli_println!();
    cli_println!(
        "{}",
        u.dim(&format!(
            "tree: {} rule(s) across {} language(s).  Each file header maps to the actual YAML file on disk.",
            total_rules,
            langs.len()
        ))
    );
    Ok(())
}

// `tree_file_rel` is re-exported through the SDK so the CLI tree
// renderer and SDK `pack_tree` JSON path produce identical paths.
// The previous CLI-local copy was byte-identical and prone to drift.

fn count_cell(u: &Ui, n: u32, thin_threshold: u32) -> String {
    if n == 0 {
        u.warn("0")
    } else if n < thin_threshold {
        u.warn(&n.to_string())
    } else {
        u.name(&n.to_string())
    }
}

fn rule_kind_str(k: RuleKind) -> &'static str {
    match k {
        RuleKind::Source => "source",
        RuleKind::Sink => "sink",
        RuleKind::Sanitizer => "sanitizer",
        RuleKind::Typing => "typing",
    }
}

// Rule family normalisation lives behind the SDK/security facade so
// JSON and text pack renderers share one canonical mapping.
