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
//! - `sink-analysis` renders the inverse view: every selected taint-relevant
//!   sink plus its source-independent upstream compiler value paths.

mod progress_ui;

use self::progress_ui::{ScopedProgress, SecurityAnalysisProgress};
use crate::args::{BrowseFormat, SecurityAction, SecurityFormat};
use crate::commands::{
    emit_json_value_paged_cached, open_project_index_filtered_paths, open_project_index_only,
    page_info_to_json, paged_json_incomplete_reasons, paging_from_cli, paging_with_row_limit,
};
use crate::footer::{render_paging_footer, render_truncation_notice};
use crate::page_cache;
use crate::paging;
use crate::ui::{extension_for, Ui};
use crate::{cli_print, cli_println, progress, ui};
use anyhow::{bail, Context, Result};
use bonsai_common::{FuncId, Span};
use bonsai_sdk::{
    load_rulepack, load_workspace_local_rules, parse_severity, security_match_rows, tree_file_rel,
    CombinedFindingWithChain, CombinedSourceAnalysisCandidate, DependencyInventoryOptions, DependencyRow,
    Finding, FindingMatch, FindingStatus, PackAuditReport, PackInventoryOptions, PackRuleRow, Rule, RuleKind,
    RuleMatch, Rulepack, RulepackMetadata, RuntimeDisabledRule, SecurityInventoryOptions, SecurityMatchRow,
    SecurityReport, Severity, SinkAnalysisCandidate, SinkAnalysisFlow, SinkAnalysisOptions,
    SourceAnalysisOptions, TaintAnalysisOptions, TaintAnalysisReport, TaintPropagationArg,
    TaintPropagationStep, TrustClass,
};
use comfy_table::Cell;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const TAINT_RENDER_CACHE_KIND: &str = "security/taint-analysis/render-report/v12";
const SINK_ANALYSIS_CACHE_KIND: &str = "security/sink-analysis/report/v1";
const SOURCE_ANALYSIS_CACHE_KIND: &str = "security/source-analysis/report/v1";
const INVENTORY_CACHE_KIND: &str = "security/inventory/v1";

/// The complete rulepack inventory of one kind over one file scope, cached
/// under the analysis scope so every rule selector is a view.
#[derive(Serialize, Deserialize)]
struct InventoryCache {
    matches: Vec<RuleMatch>,
}

const DEPS_INVENTORY_CACHE_KIND: &str = "security/deps-inventory/v2";

/// Complete dependency inventory for one file scope.
#[derive(Clone, Serialize, Deserialize)]
struct DepsInventoryCache {
    inventory: bonsai_sdk::DependencyInventory,
}

/// Compute (or reuse) the complete inventory for `kind` — every enabled rule
/// of that kind over `files` / `exclude_files` — then narrow it to the
/// request's rule selection by rule id. The scan never re-runs for a
/// different `--rule`, `--severity`, `--tag`, `--category`, or `--trust`.
fn inventory_view(
    workspace: &Path,
    project: &bonsai_sdk::Project,
    pack: &Rulepack,
    kind: RuleKind,
    options: &SecurityInventoryOptions,
    progress: &mut SecurityAnalysisProgress,
) -> Result<Vec<RuleMatch>> {
    let kind_label = match kind {
        RuleKind::Source => "source",
        RuleKind::Sink => "sink",
        RuleKind::Sanitizer => "sanitizer",
        RuleKind::Typing => "typing",
    };
    let complete = complete_inventory(workspace, project, kind, kind_label, options, progress)?;
    let selected = bonsai_sdk::inventory_rule_ids(pack, kind, options)?;
    Ok(complete
        .into_iter()
        .filter(|matched| selected.contains(&matched.rule_id))
        .collect())
}

/// The complete inventory of `kind` for the file scope in `options`: read
/// from the keyed payload when present, otherwise scanned once and saved so
/// every later view (and dependency-analysis) reuses it.
fn complete_inventory(
    workspace: &Path,
    project: &bonsai_sdk::Project,
    kind: RuleKind,
    kind_label: &str,
    options: &SecurityInventoryOptions,
    progress: &mut SecurityAnalysisProgress,
) -> Result<Vec<RuleMatch>> {
    let files_filter = options.files.join(",");
    let exclude_files_filter = options.exclude_files.join(",");
    let analysis_hash = filter_signature(&[
        ("kind", kind_label),
        ("files", &files_filter),
        ("exclude_files", &exclude_files_filter),
    ]);
    let cached: Option<InventoryCache> =
        page_cache::read_keyed_payload(workspace, analysis_hash, INVENTORY_CACHE_KIND)?;
    if let Some(cached) = cached {
        return Ok(cached.matches);
    }
    let complete_options = SecurityInventoryOptions {
        files: options.files.clone(),
        exclude_files: options.exclude_files.clone(),
        ..Default::default()
    };
    let matches = match kind {
        RuleKind::Source => project
            .security()
            .sources_with_progress(complete_options, |event| progress.handle(event))?,
        RuleKind::Sink => project
            .security()
            .sinks_with_progress(complete_options, |event| progress.handle(event))?,
        RuleKind::Sanitizer => project
            .security()
            .sanitizers_with_progress(complete_options, |event| progress.handle(event))?,
        RuleKind::Typing => Vec::new(),
    };
    page_cache::save_keyed_payload(
        workspace,
        analysis_hash,
        INVENTORY_CACHE_KIND,
        &InventoryCache {
            matches: matches.clone(),
        },
    )?;
    Ok(matches)
}

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
    /// Rulepack-owned prose and taxonomy used by every renderer. Keeping this
    /// on the canonical row prevents text from possessing information that
    /// JSON cannot expose and makes secondary filters operate on the complete
    /// finding object.
    #[serde(default)]
    presentation: TaintFindingPresentation,
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

/// Complete sink-analysis report persisted under the analysis scope so every
/// selector re-query is a view instead of a rerun. Chain functions are stored
/// as raw ids; the keyed payload is invalidated with the workspace
/// fingerprint, so those ids stay valid for the cached generation.
#[derive(Serialize, Deserialize)]
struct SinkAnalysisReportCache {
    candidates: Vec<SinkAnalysisCandidateCache>,
    source_rule_count: usize,
    sink_rule_count: usize,
    sanitizer_rule_count: usize,
    #[serde(default)]
    analysis_complete: bool,
    #[serde(default)]
    analysis_incomplete_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    runtime_disabled_rules: Vec<RuntimeDisabledRule>,
}

/// Complete source-analysis report persisted under the analysis scope.
#[derive(Serialize, Deserialize)]
struct SourceAnalysisReportCache {
    candidates: Vec<SourceAnalysisCandidateCache>,
    source_rule_count: usize,
    #[serde(default)]
    analysis_complete: bool,
    #[serde(default)]
    analysis_incomplete_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    runtime_disabled_rules: Vec<RuntimeDisabledRule>,
}

#[derive(Serialize, Deserialize)]
struct SourceAnalysisCandidateCache {
    source: FindingMatch,
    chain_names: Vec<String>,
    path: Vec<u32>,
    flow_id: String,
    taint_path: Vec<TaintPropagationStep>,
    additional_sources: Vec<FindingMatch>,
}

impl From<&CombinedSourceAnalysisCandidate> for SourceAnalysisCandidateCache {
    fn from(candidate: &CombinedSourceAnalysisCandidate) -> Self {
        Self {
            source: candidate.source.clone(),
            chain_names: candidate.chain_names.clone(),
            path: candidate.path.iter().map(|func| func.raw()).collect(),
            flow_id: candidate.flow_id.clone(),
            taint_path: candidate.taint_path.clone(),
            additional_sources: candidate.additional_sources.clone(),
        }
    }
}

impl From<SourceAnalysisCandidateCache> for CombinedSourceAnalysisCandidate {
    fn from(cached: SourceAnalysisCandidateCache) -> Self {
        Self {
            source: cached.source,
            chain_names: cached.chain_names,
            path: cached.path.into_iter().map(bonsai_common::FuncId::new).collect(),
            flow_id: cached.flow_id,
            taint_path: cached.taint_path,
            additional_sources: cached.additional_sources,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SinkAnalysisCandidateCache {
    sink: FindingMatch,
    upstream_flows: Vec<SinkAnalysisFlowCache>,
    security_source_flows: Vec<CombinedFindingWithChain>,
}

#[derive(Serialize, Deserialize)]
struct SinkAnalysisFlowCache {
    flow_id: String,
    origin_function: String,
    origin_file: String,
    origin_line: u32,
    chain_names: Vec<String>,
    chain_func_ids: Vec<u32>,
    taint_path: Vec<TaintPropagationStep>,
    endpoint_only: bool,
}

impl From<&SinkAnalysisCandidate> for SinkAnalysisCandidateCache {
    fn from(candidate: &SinkAnalysisCandidate) -> Self {
        Self {
            sink: candidate.sink.clone(),
            upstream_flows: candidate
                .upstream_flows
                .iter()
                .map(|flow| SinkAnalysisFlowCache {
                    flow_id: flow.flow_id.clone(),
                    origin_function: flow.origin_function.clone(),
                    origin_file: flow.origin_file.clone(),
                    origin_line: flow.origin_line,
                    chain_names: flow.chain_names.clone(),
                    chain_func_ids: flow.chain_funcs.iter().map(|func| func.raw()).collect(),
                    taint_path: flow.taint_path.clone(),
                    endpoint_only: flow.endpoint_only,
                })
                .collect(),
            security_source_flows: candidate.security_source_flows.clone(),
        }
    }
}

impl From<SinkAnalysisCandidateCache> for SinkAnalysisCandidate {
    fn from(cached: SinkAnalysisCandidateCache) -> Self {
        Self {
            sink: cached.sink,
            upstream_flows: cached
                .upstream_flows
                .into_iter()
                .map(|flow| bonsai_sdk::SinkAnalysisFlow {
                    flow_id: flow.flow_id,
                    origin_function: flow.origin_function,
                    origin_file: flow.origin_file,
                    origin_line: flow.origin_line,
                    chain_names: flow.chain_names,
                    chain_funcs: flow
                        .chain_func_ids
                        .into_iter()
                        .map(bonsai_common::FuncId::new)
                        .collect(),
                    taint_path: flow.taint_path,
                    endpoint_only: flow.endpoint_only,
                })
                .collect(),
            security_source_flows: cached.security_source_flows,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TaintAnalysisRenderFindingCache {
    #[serde(flatten)]
    finding: CombinedFindingWithChain,
    #[serde(default)]
    presentation: TaintFindingPresentation,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    chain_func_ids: Vec<u32>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct TaintFindingPresentation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    packages: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    frameworks: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    rules: BTreeMap<String, TaintRulePresentation>,
}

#[derive(Clone, Serialize, Deserialize)]
struct TaintRulePresentation {
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust: Option<TrustClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cwe: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    owasp: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    packages: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    frameworks: Vec<String>,
}

/// Render-only selection over one canonical taint result. None of these
/// values changes compiler lowering, source/sink matching, or IDG closure;
/// consequently none belongs in the semantic analysis cache key.
#[derive(Clone)]
struct TaintViewFilters {
    source: Option<Regex>,
    finding: Option<String>,
    flow: Option<String>,
    group: Option<String>,
    trust: Option<String>,
    category: Option<String>,
    sink: Option<Regex>,
    severity: Option<Severity>,
    tag: Option<String>,
    include_pattern_only: bool,
    show_sanitized: bool,
    /// Rule aliases from the loaded pack. `--source` / `--sink` selectors
    /// match a rule by its canonical id or any alias, exactly like the SDK
    /// analysis-level selectors, so a renamed rule keeps its old spelling.
    aliases_by_rule: std::collections::BTreeMap<String, Vec<String>>,
}

impl TaintViewFilters {
    #[allow(clippy::too_many_arguments)]
    fn compile(
        pack: &Rulepack,
        source: Option<&str>,
        finding: Option<String>,
        flow: Option<String>,
        group: Option<String>,
        trust: Option<String>,
        category: Option<String>,
        sink: Option<&str>,
        severity: Option<Severity>,
        tag: Option<String>,
        include_pattern_only: bool,
        show_sanitized: bool,
    ) -> Result<Self> {
        let source_regex = source
            .map(Regex::new)
            .transpose()
            .with_context(|| format!("invalid --source regex `{}`", source.unwrap_or_default()))?;
        let sink_regex = sink
            .map(Regex::new)
            .transpose()
            .with_context(|| format!("invalid --sink regex `{}`", sink.unwrap_or_default()))?;
        let aliases_by_rule = pack
            .all_rules()
            .into_iter()
            .filter(|rule| !rule.aliases.is_empty())
            .map(|rule| (rule.id.clone(), rule.aliases.clone()))
            .collect();
        Ok(Self {
            source: source_regex,
            finding,
            flow,
            group,
            trust,
            category,
            sink: sink_regex,
            severity,
            tag,
            include_pattern_only,
            show_sanitized,
            aliases_by_rule,
        })
    }

    fn rule_matches(&self, regex: &Regex, rule_id: &str) -> bool {
        regex.is_match(rule_id)
            || self
                .aliases_by_rule
                .get(rule_id)
                .is_some_and(|aliases| aliases.iter().any(|alias| regex.is_match(alias)))
    }

    fn has_identity_selector(&self) -> bool {
        self.finding.is_some() || self.flow.is_some() || self.group.is_some()
    }

    /// Sink-analysis view: keep a sink when its rule/severity/tag pass, and
    /// keep only the security-source proofs whose source passes the source
    /// selectors. Source selectors never drop a sink; a sink with no matching
    /// proof stays visible with its source-independent lineage.
    fn retain_sink_candidate(&self, candidate: &mut SinkAnalysisCandidate) -> bool {
        if self
            .sink
            .as_ref()
            .is_some_and(|regex| !self.rule_matches(regex, &candidate.sink.rule_id))
        {
            return false;
        }
        if self
            .severity
            .is_some_and(|floor| candidate.sink.severity.is_none_or(|value| value < floor))
        {
            return false;
        }
        if self
            .tag
            .as_deref()
            .is_some_and(|tag| candidate.sink.tag.as_deref() != Some(tag))
        {
            return false;
        }
        if self.source.is_some() || self.trust.is_some() || self.category.is_some() {
            candidate
                .security_source_flows
                .retain(|proof| self.matches(proof));
        }
        true
    }

    /// Source-analysis view: keep a flow when its primary source or any
    /// additional source passes the source rule / trust / category / tag
    /// selectors. Sources are evidence and are never removed from a kept
    /// flow.
    fn retain_source_candidate(&self, candidate: &CombinedSourceAnalysisCandidate) -> bool {
        std::iter::once(&candidate.source)
            .chain(candidate.additional_sources.iter())
            .any(|source| {
                self.source
                    .as_ref()
                    .is_none_or(|regex| self.rule_matches(regex, &source.rule_id))
                    && self
                        .trust
                        .as_deref()
                        .is_none_or(|trust| source.trust.as_deref() == Some(trust))
                    && self
                        .category
                        .as_deref()
                        .is_none_or(|category| source.category.as_deref() == Some(category))
                    && self
                        .tag
                        .as_deref()
                        .is_none_or(|tag| source.tag.as_deref() == Some(tag))
            })
    }

    fn matches(&self, combined: &CombinedFindingWithChain) -> bool {
        self.reject_reason(combined).is_none()
    }

    /// The first selector that hides `combined`, or `None` when the view
    /// shows it. Reasons are stable labels reported in the summary's
    /// `view.hidden` map.
    fn reject_reason(&self, combined: &CombinedFindingWithChain) -> Option<&'static str> {
        let finding = &combined.finding;
        if !self.include_pattern_only && finding.source.rule_id.starts_with("pattern:") {
            return Some("pattern-only");
        }
        if !self.show_sanitized && finding.status == FindingStatus::Sanitized {
            return Some("sanitized");
        }
        if self
            .severity
            .is_some_and(|floor| finding.severity.is_none_or(|value| value < floor))
        {
            return Some("severity");
        }
        if self.finding.as_deref().is_some_and(|id| {
            finding.finding_id != id && !combined.member_finding_ids.iter().any(|member| member == id)
        }) {
            return Some("stable-id");
        }
        if self
            .flow
            .as_deref()
            .is_some_and(|id| !finding.flow_ids().any(|flow| flow == id))
        {
            return Some("stable-id");
        }
        if self
            .group
            .as_deref()
            .is_some_and(|id| finding.group_id.as_deref() != Some(id))
        {
            return Some("stable-id");
        }

        let sources = std::iter::once(&finding.source)
            .chain(combined.additional_sources.iter())
            .chain(finding.alternate_flows.iter().map(|flow| &flow.source));
        let source_matches = sources.clone().any(|source| {
            self.source
                .as_ref()
                .is_none_or(|regex| self.rule_matches(regex, &source.rule_id))
                && self
                    .trust
                    .as_deref()
                    .is_none_or(|trust| source.trust.as_deref() == Some(trust))
                && self
                    .category
                    .as_deref()
                    .is_none_or(|category| source.category.as_deref() == Some(category))
        });
        if !source_matches {
            // Attribute to the trust narrower when it alone would have
            // hidden every source; otherwise to the source selectors.
            let trust_only = self.trust.as_deref().is_some_and(|trust| {
                !sources
                    .clone()
                    .any(|source| source.trust.as_deref() == Some(trust))
            });
            return Some(if trust_only { "trust" } else { "source" });
        }

        let sinks = std::iter::once(&finding.sink).chain(combined.additional_sinks.iter());
        if !sinks.clone().any(|sink| {
            self.sink
                .as_ref()
                .is_none_or(|regex| self.rule_matches(regex, &sink.rule_id))
                && self
                    .tag
                    .as_deref()
                    .is_none_or(|tag| finding.tag.as_deref() == Some(tag) || sink.tag.as_deref() == Some(tag))
        }) {
            return Some("sink");
        }
        None
    }

    /// Flags that reveal findings hidden for `reason`.
    fn widen_flags(reason: &str) -> &'static [&'static str] {
        match reason {
            "trust" => &["--profile all", "or --trust <class>"],
            "pattern-only" => &["--include-pattern-only"],
            "sanitized" => &["--show-sanitized"],
            "severity" => &["--severity low"],
            _ => &[],
        }
    }
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
                    presentation: item.presentation.clone(),
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
                    presentation: item.presentation,
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

/// What a taint view hides from the complete cached report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct TaintViewSummary {
    /// Source trust class in force (`--trust` or the review profile's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trust: Option<String>,
    /// Complete findings in the analysis before any view selector.
    complete_findings: usize,
    /// Findings hidden by each selector, keyed by the first selector that
    /// rejected the finding (`trust`, `pattern-only`, `sanitized`,
    /// `severity`, `stable-id`, `source`, `sink`, `text`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    hidden: BTreeMap<String, usize>,
    /// Total hidden findings.
    hidden_total: usize,
    /// Flags that reveal the hidden findings, in the order they apply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    widen: Vec<String>,
}

impl TaintViewSummary {
    fn widen_hint(&self) -> String {
        if self.widen.is_empty() {
            String::new()
        } else {
            format!(" — widen with {}", self.widen.join(" "))
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
    /// Effective sink-severity floor after applying the selected review
    /// profile and explicit CLI overrides. This is output metadata only; the
    /// semantic request already carries the parsed severity constraint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    severity_floor: Option<String>,
    /// Present when the rendered report is a narrowed view of the complete
    /// analysis: which selectors are in force and how many complete
    /// findings they hide, so an empty page is never mistaken for a clean
    /// workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    view: Option<TaintViewSummary>,
    severity_counts: BTreeMap<String, usize>,
    status_counts: BTreeMap<String, usize>,
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
    cmd_security_with_profile_default(workspace, action, true)
}

/// Reopen a stable security id without applying a review profile. Findings
/// may have been produced under any rulepack-declared profile, so `show` must
/// query the complete semantic result rather than guess a profile spelling.
/// Run a security action under the same default profile a plain
/// `security taint-analysis` run uses. `show S:/F:/G:` reopens ids that
/// run minted, so it must key the same cached complete report instead of
/// recomputing an unprofiled one.
pub(crate) fn cmd_security_default_profile(workspace: &Path, action: SecurityAction) -> Result<()> {
    cmd_security_with_profile_default(workspace, action, true)
}

/// Runs the action with no review profile applied: the complete rulepack
/// result, a superset of every profiled view. Stable-id reopening uses it as
/// the generic fallback when an id is absent from the cached default view.
pub(crate) fn cmd_security_unprofiled(workspace: &Path, action: SecurityAction) -> Result<()> {
    cmd_security_with_profile_default(workspace, action, false)
}

/// A stable id (`S:`/`F:`/`G:`) selected nothing in the report the command
/// rendered. Typed so callers can widen the search (another profile) instead
/// of parsing the message.
#[derive(Debug)]
pub(crate) struct MissingStableId {
    pub(crate) kind: &'static str,
    pub(crate) id: String,
}

impl std::fmt::Display for MissingStableId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no {} matching `{}` in this workspace", self.kind, self.id)
    }
}

impl std::error::Error for MissingStableId {}

fn cmd_security_with_profile_default(
    workspace: &Path,
    action: SecurityAction,
    apply_default_profile: bool,
) -> Result<()> {
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
        | SecurityAction::DependencyAnalysis { rules_dir, .. }
        | SecurityAction::TaintAnalysis { rules_dir, .. }
        | SecurityAction::SourceAnalysis { rules_dir, .. }
        | SecurityAction::SinkAnalysis { rules_dir, .. }
        | SecurityAction::Pack { rules_dir, .. } => rules_dir.as_deref(),
    };
    let rules_dir = resolve_rules_dir(workspace, action_rules_dir)?;
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
        SecurityAction::DependencyAnalysis {
            rules_dir: _,
            framework,
            mut severity,
            files,
            mut exclude_files,
            mut context,
            page,
            all,
            format,
            output: _,
        } => {
            // Same review profile as taint-analysis: identical scope means
            // the two commands share one complete taint report payload.
            let mut exclude_tests = false;
            let mut trust = None;
            apply_profile(
                &pack.metadata,
                selected_security_profile(&pack.metadata, None, apply_default_profile),
                ProfileOverrides {
                    trust: &mut trust,
                    severity: Some(&mut severity),
                    exclude_files: &mut exclude_files,
                    exclude_tests: Some(&mut exclude_tests),
                    context: &mut context,
                },
            )?;
            let paging_cfg = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_dependency_analysis(
                workspace,
                &pack,
                &rules_dir,
                framework,
                severity,
                files,
                exclude_files,
                exclude_tests,
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
                selected_security_profile(&pack.metadata, profile.as_deref(), apply_default_profile),
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
                selected_security_profile(&pack.metadata, profile.as_deref(), apply_default_profile),
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
        SecurityAction::SinkAnalysis {
            rules_dir: _,
            profile,
            source,
            mut trust,
            category,
            sink,
            mut severity,
            tag,
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
                selected_security_profile(&pack.metadata, profile.as_deref(), apply_default_profile),
                ProfileOverrides {
                    trust: &mut trust,
                    severity: Some(&mut severity),
                    exclude_files: &mut exclude_files,
                    exclude_tests: Some(&mut exclude_tests),
                    context: &mut context,
                },
            )?;
            let severity = parse_severity_flag(severity.as_deref())?;
            let paging_cfg = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_sink_analysis(
                workspace,
                &pack,
                &rules_dir,
                source,
                trust,
                category,
                sink,
                severity,
                tag,
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
            tag,
            rule,
            state,
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
                tag,
                rule,
                state,
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

fn selected_security_profile<'a>(
    metadata: &'a RulepackMetadata,
    requested: Option<&'a str>,
    apply_default: bool,
) -> Option<&'a str> {
    if requested.is_some() || !apply_default {
        requested
    } else {
        metadata.default_profile.as_deref()
    }
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
/// use the SDK's centralized external discovery and built-in fallback.
fn resolve_rules_dir(workspace: &Path, rules_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(d) = rules_dir {
        return Ok(d.to_path_buf());
    }
    bonsai_sdk::Bonsai::default_rulepack_root(workspace)
        .map_err(|error| anyhow::anyhow!("security: bundled rulepack is unavailable: {error:#}"))
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
    let (project, _footer) = if !files.is_empty() || !exclude_files.is_empty() {
        open_security_project_filtered_paths(workspace, pack, rules_dir, &files, &exclude_files)?
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
    let matches = inventory_view(
        workspace,
        &project,
        pack,
        RuleKind::Source,
        &options,
        &mut analysis_progress,
    )?;
    render_match_table(
        workspace,
        project.workspace(),
        "sources",
        &matches,
        pack,
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
    let matches = inventory_view(
        workspace,
        &project,
        pack,
        RuleKind::Sink,
        &SecurityInventoryOptions {
            rule: rule.clone(),
            rule_regex: rule_regex.clone(),
            severity: sev_floor,
            tag: tag.clone(),
            category: category.clone(),
            files: files.clone(),
            exclude_files: exclude_files.clone(),
            ..Default::default()
        },
        &mut analysis_progress,
    )?;
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "sink inventory analysis complete: {:.3}s matches={}",
        command_started.elapsed().as_secs_f64(),
        matches.len()
    );
    let result = render_match_table(
        workspace,
        project.workspace(),
        "sinks",
        &matches,
        pack,
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
    let matches = inventory_view(
        workspace,
        &project,
        pack,
        RuleKind::Sanitizer,
        &SecurityInventoryOptions {
            rule: rule.clone(),
            rule_regex: rule_regex.clone(),
            tag: tag.clone(),
            severity: sev_floor,
            category: category.clone(),
            files: files.clone(),
            exclude_files: exclude_files.clone(),
            ..Default::default()
        },
        &mut analysis_progress,
    )?;
    render_match_table(
        workspace,
        project.workspace(),
        "sanitizers",
        &matches,
        pack,
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
    let severity_floor = parse_severity_flag(severity.as_deref())?;
    // The complete inventory for the file scope is a cached object;
    // framework and severity are views over it, rendered from the rows and
    // the loaded rulepack without opening the workspace.
    let files_filter = files.join(",");
    let exclude_files_filter = exclude_files.join(",");
    let inventory_hash = filter_signature(&[
        ("kind", "deps-inventory"),
        ("files", &files_filter),
        ("exclude_files", &exclude_files_filter),
    ]);
    let cached: Option<DepsInventoryCache> =
        page_cache::read_keyed_payload(workspace, inventory_hash, DEPS_INVENTORY_CACHE_KIND)?;
    let mut inv = match cached {
        Some(cached) => cached.inventory,
        None => {
            let (project, _footer) = if !files.is_empty() || !exclude_files.is_empty() {
                open_security_project_filtered_paths(workspace, pack, rules_dir, &files, &exclude_files)?
            } else {
                open_security_project(workspace, pack, rules_dir)?
            };
            let collect_progress = ScopedProgress::new("collecting dependency inventory");
            let inv = project.security().deps(DependencyInventoryOptions {
                framework: None,
                severity: None,
                files: files.clone(),
                exclude_files: exclude_files.clone(),
            })?;
            collect_progress.finish();
            page_cache::save_keyed_payload(
                workspace,
                inventory_hash,
                DEPS_INVENTORY_CACHE_KIND,
                &DepsInventoryCache {
                    inventory: inv.clone(),
                },
            )?;
            inv
        }
    };
    // Same selectors the SDK inventory applies, as a view.
    if let Some(framework) = framework.as_deref() {
        inv.rows.retain(|row| {
            row.key == framework || row.signals.iter().any(|signal| signal.contains(framework))
        });
    }
    if let Some(floor) = severity_floor {
        inv.rows
            .retain(|row| row.severity.is_some_and(|row_severity| row_severity >= floor));
    }

    let filters_hash = filter_signature(&[
        ("kind", "deps"),
        ("framework", framework.as_deref().unwrap_or("")),
        ("severity", severity.as_deref().unwrap_or("")),
    ]);
    let rows = dependency_presentation_rows(&inv.rows, pack);
    let cost = |r: &DependencyPresentationRow| dep_block_cost_bytes(r);

    match format {
        BrowseFormat::Json => {
            page_cache::emit_paged_text(
                workspace,
                &rows,
                &paging_cfg,
                "security/deps",
                filters_hash,
                cost,
                |paged, info, _cfg| {
                    let result_complete = info.page_number == 1 && info.is_last;
                    let payload = serde_json::json!({
                        "analysis_complete": inv.analysis_complete,
                        "analysis_incomplete_reasons": inv.analysis_incomplete_reasons,
                        "result_complete": result_complete,
                        "result_incomplete_reasons": if result_complete {
                            Vec::<String>::new()
                        } else {
                            paged_json_incomplete_reasons("security/deps", info)
                        },
                        "page": page_info_to_json(info),
                        "rows": paged,
                    });
                    crate::output::emit_json_document(&payload)?;
                    Ok(())
                },
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                workspace,
                &rows,
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
                    let rows: Vec<DependencyPresentationRow> = if limit_eff == 0 {
                        paged.to_vec()
                    } else {
                        paged.iter().take(limit_eff).cloned().collect()
                    };
                    let u = ui();
                    cli_println!(
                        "{}",
                        u.dim(&format!("security deps — {} package(s)", info.total_rows))
                    );
                    if !inv.analysis_complete {
                        cli_println!(
                            "analysis: incomplete — {}",
                            inv.analysis_incomplete_reasons.join("; ")
                        );
                    }
                    render_dependency_table(u, &rows);
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
    let view_filters = TaintViewFilters::compile(
        pack,
        source.as_deref(),
        finding.clone(),
        flow.clone(),
        group.clone(),
        trust.clone(),
        category.clone(),
        sink.as_deref(),
        sev_floor,
        tag.clone(),
        include_pattern_only,
        show_sanitized,
    )?;

    // Semantic scope contains only inputs that change what the workspace
    // is: file include/exclude scope, test exclusion, and inferred-source
    // seeding. The complete report seeds every source rule and terminates at
    // every sink rule; `--source`, `--trust`, `--category`, `--sink` (and the
    // profile's trust default), severity, tag, stable-id, status,
    // pattern-only, and text selectors are all views over that cached report
    // and deliberately do not enter this key, so a narrowed re-query never
    // reruns parsing, callgraph, IDG, or taint work.
    let files_filter = files.join(",");
    let exclude_files_filter = exclude_files.join(",");
    let analysis_hash = filter_signature(&[
        ("kind", "taint-analysis"),
        ("files", &files_filter),
        ("exclude_files", &exclude_files_filter),
        ("inferred_sources", if inferred_sources { "1" } else { "0" }),
        ("exclude_tests", if exclude_tests { "1" } else { "0" }),
    ]);
    let analysis_hash_text = format!("{analysis_hash:016x}");
    let secondary_hash_text = format!("{:016x}", crate::filter::active().signature());
    let view_hash = filter_signature(&[
        ("analysis", &analysis_hash_text),
        ("source", source.as_deref().unwrap_or("")),
        ("finding", finding.as_deref().unwrap_or("")),
        ("flow", flow.as_deref().unwrap_or("")),
        ("group", group.as_deref().unwrap_or("")),
        ("trust", trust.as_deref().unwrap_or("")),
        ("category", category.as_deref().unwrap_or("")),
        ("sink", sink.as_deref().unwrap_or("")),
        ("severity", severity.as_deref().unwrap_or("")),
        ("tag", tag.as_deref().unwrap_or("")),
        ("show_sanitized", if show_sanitized { "1" } else { "0" }),
        (
            "include_pattern_only",
            if include_pattern_only { "1" } else { "0" },
        ),
        ("secondary", &secondary_hash_text),
    ]);

    // `--explain` needs live endpoint inventories. Every ordinary render,
    // including stable-id and SARIF views, reuses the same compact canonical
    // report; flow bodies hydrate lazily from compiler objects for selected
    // rows only.
    if !explain {
        if let Some(cached_report) = page_cache::read_keyed_payload::<TaintAnalysisRenderReportCache>(
            workspace,
            analysis_hash,
            TAINT_RENDER_CACHE_KIND,
        )? {
            let cached_report = TaintAnalysisRenderReport::from(cached_report);
            if !summary_only && cached_report.findings.is_empty() && cached_report.summary.total_findings > 0
            {
                tracing::debug!(
                    "ignoring taint render cache payload with summary count but no finding bodies"
                );
            } else if matches!(format, SecurityFormat::Sarif) {
                // SARIF is one more view over the complete cached report:
                // hydrate flow evidence for its findings when the payload was
                // saved without bulk evidence, then serialize.
                let (project, _footer) = if !files.is_empty() || !exclude_files.is_empty() {
                    open_security_project_filtered_paths(workspace, pack, rules_dir, &files, &exclude_files)?
                } else {
                    open_security_project(workspace, pack, rules_dir)?
                };
                let render_progress = ScopedProgress::new("rendering cached SARIF");
                let mut findings = cached_report.findings.clone();
                if !cached_report.bulk_flow_evidence {
                    let mut body_cache = bonsai_sdk::FlowBodyCache::new(project.workspace());
                    for item in &mut findings {
                        attach_flow_evidence_to_render_finding(&mut body_cache, item);
                    }
                }
                let combined: Vec<CombinedFindingWithChain> =
                    findings.into_iter().map(|item| item.finding).collect();
                emit_taint_sarif(
                    workspace,
                    combined,
                    cached_report.runtime_disabled_rules.clone(),
                    cached_report.analysis_complete,
                    cached_report.analysis_incomplete_reasons.clone(),
                    &view_filters,
                )?;
                render_progress.finish();
                return Ok(());
            } else {
                let cached_render_project = if !summary_only {
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
                    analysis_hash,
                    view_hash,
                    &view_filters,
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
            // The engine computes the complete report; every rule selector
            // is applied as a view when rendering. `--explain` is the one
            // live-inventory mode and keeps its selectors.
            source: if explain { source.clone() } else { None },
            flow_id: None,
            trust: if explain { trust.clone() } else { None },
            category: if explain { category.clone() } else { None },
            sink: if explain { sink.clone() } else { None },
            severity: if explain { sev_floor } else { None },
            tag: if explain { tag.clone() } else { None },
            files: files.clone(),
            exclude_files: exclude_files.clone(),
            include_inferred_sources: inferred_sources,
            include_pattern_only: true,
            show_sanitized: true,
            exclude_tests,
            attach_flow_evidence: false,
            taint_graph_resident_cache_entries: Some(0),
        },
        |event| analysis_progress.handle(event),
    )?;
    let runtime_disabled_rules = report.runtime_disabled_rules.clone();
    let bulk_flow_evidence_attached = matches!(format, SecurityFormat::Sarif);
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
            // The complete report (with bulk flow evidence) is persisted
            // first so later text, JSON, and SARIF views reuse it instead of
            // re-running the analysis.
            let render_report = build_taint_render_report(report.clone(), pack, true, true);
            save_taint_payload_if_requested(
                workspace,
                analysis_hash,
                view_hash,
                Vec::new(),
                Some(&render_report),
            );
            let render_progress = ScopedProgress::new("rendering SARIF");
            let TaintAnalysisReport {
                findings,
                analysis_complete,
                analysis_incomplete_reasons,
                ..
            } = report;
            emit_taint_sarif(
                workspace,
                findings,
                runtime_disabled_rules,
                analysis_complete,
                analysis_incomplete_reasons,
                &view_filters,
            )?;
            render_progress.finish();
            return Ok(());
        }
        SecurityFormat::Json | SecurityFormat::Text => {}
    }

    // Findings are always part of the persisted report: a `--summary` run
    // warms the same cache every later view reads.
    let mut render_report = build_taint_render_report(report, pack, true, bulk_flow_evidence_attached);
    render_report.summary.severity_floor.clone_from(&severity);
    let render_progress = ScopedProgress::new(if summary_only {
        "rendering taint summary"
    } else if matches!(format, SecurityFormat::Json) {
        "rendering taint JSON"
    } else {
        "rendering taint page"
    });
    emit_taint_render_report(
        workspace,
        if !summary_only {
            Some(project.workspace())
        } else {
            None
        },
        pack,
        &render_report,
        &paging_cfg,
        summary_only,
        format,
        analysis_hash,
        view_hash,
        &view_filters,
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
    analysis_hash: u64,
    view_hash: u64,
    view_filters: &TaintViewFilters,
    cache_payload: Option<&TaintAnalysisRenderReport>,
    baseline_ids: Option<&std::collections::BTreeSet<String>>,
) -> Result<()> {
    // Both the secondary `--contains` filter and the `--baseline` diff
    // are RENDER-time: they shape what prints over an owned copy, while
    // `cache_payload` keeps pointing at the unfiltered, un-baselined
    // report — so the cached analysis is reused regardless of either.
    let mut owned = Some(filter_taint_render_report(
        report,
        render_workspace,
        view_filters,
    )?);
    if let Some(ids) = baseline_ids {
        let target = owned.as_mut().expect("filtered taint report is present");
        let diff = apply_baseline(target, ids);
        target.baseline = Some(diff);
    }
    let report = owned.as_ref().expect("filtered taint report is present");
    emit_taint_render_report_inner(
        workspace,
        render_workspace,
        pack,
        report,
        paging_cfg,
        summary_only,
        format,
        analysis_hash,
        view_hash,
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
    analysis_hash: u64,
    view_hash: u64,
    cache_payload: Option<&TaintAnalysisRenderReport>,
) -> Result<()> {
    match format {
        SecurityFormat::Json if summary_only => {
            let mut summary = serde_json::to_value(&report.summary)?;
            if let (Some(diff), Some(fields)) = (report.baseline.as_ref(), summary.as_object_mut()) {
                fields.insert("baseline".to_string(), serde_json::to_value(diff)?);
            }
            crate::output::emit_json_document(&summary)?;
            save_taint_payload_if_requested(workspace, analysis_hash, view_hash, Vec::new(), cache_payload);
        }
        SecurityFormat::Text if summary_only => {
            let text = page_cache::capture(|| {
                render_taint_summary_text(&report.summary);
                if let Some(diff) = report.baseline.as_ref() {
                    render_baseline_summary_text(diff);
                }
                Ok(())
            })?;
            save_taint_payload_if_requested(workspace, analysis_hash, view_hash, Vec::new(), cache_payload);
            page_cache::emit_cached_text(&text)?;
        }
        SecurityFormat::Json => {
            let (pages, current_page) =
                build_taint_json_pages(render_workspace, report, paging_cfg, view_hash)?;
            save_taint_payload_if_requested(
                workspace,
                analysis_hash,
                view_hash,
                pages.clone(),
                cache_payload,
            );
            emit_cached_page(&pages, current_page)?;
        }
        SecurityFormat::Text => {
            let (pages, current_page) =
                build_taint_text_pages(workspace, render_workspace, pack, report, paging_cfg, view_hash)?;
            save_taint_payload_if_requested(
                workspace,
                analysis_hash,
                view_hash,
                pages.clone(),
                cache_payload,
            );
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
    analysis_hash: u64,
    view_hash: u64,
    pages: Vec<page_cache::CachedPage>,
    payload: Option<&TaintAnalysisRenderReport>,
) {
    // Rendered pages key on the full argv (format / paging / secondary
    // filter) — they ARE the shaped output, so each variant caches its
    // own bytes for an identical re-run.
    if !pages.is_empty() {
        if let Err(e) = page_cache::save_pages(workspace, "security/taint-analysis", view_hash, pages) {
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
                analysis_hash,
                TAINT_RENDER_CACHE_KIND,
            ) {
                if existing.bulk_flow_evidence {
                    return;
                }
            }
        }
        if let Err(e) =
            page_cache::save_keyed_payload(workspace, analysis_hash, TAINT_RENDER_CACHE_KIND, &cache_payload)
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

/// SARIF 2.1.0 — direct serialization, no pagination. Standardised SAST
/// output expected by IDE integrations and GitHub code scanning; consumers
/// expect the full selected result set in one document.
fn emit_taint_sarif(
    workspace: &Path,
    mut findings: Vec<CombinedFindingWithChain>,
    runtime_disabled_rules: Vec<RuntimeDisabledRule>,
    analysis_complete: bool,
    analysis_incomplete_reasons: Vec<String>,
    view_filters: &TaintViewFilters,
) -> Result<()> {
    findings
        .retain(|finding| view_filters.matches(finding) && crate::filter::active().matches_value(finding));
    ensure_selected_taint_view_exists(findings.len(), view_filters)?;
    let plain: Vec<Finding> = findings.iter().map(|f| f.finding.clone()).collect();
    // Runtime-disabled rules collected by the matcher (invalid regex, etc.)
    // surface alongside findings; rules silently dropped at runtime would
    // otherwise never reach the user.
    let report = SecurityReport::with_runtime_disabled_rules(plain, runtime_disabled_rules)
        .with_analysis_completeness(analysis_complete, analysis_incomplete_reasons);
    let workspace_root = std::fs::canonicalize(workspace)
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned))
        .unwrap_or_else(|| workspace.to_string_lossy().into_owned());
    cli_println!("{}", report.sarif_json_with_workspace_root(&workspace_root));
    Ok(())
}

fn attach_flow_evidence_to_report(ws: &bonsai_sdk::Workspace, report: &mut TaintAnalysisReport) {
    let mut body_cache = bonsai_sdk::FlowBodyCache::new(ws);
    for combined in &mut report.findings {
        if combined.finding.hops.is_empty() {
            combined.finding.hops = body_cache.build_flow_bodies(
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

fn attach_flow_evidence_to_render_finding(
    body_cache: &mut bonsai_sdk::FlowBodyCache<'_>,
    item: &mut TaintAnalysisRenderFinding,
) {
    if !item.finding.finding.hops.is_empty() {
        return;
    }
    let chain_funcs = render_chain_funcs(item);
    if chain_funcs.is_empty() {
        return;
    }
    item.finding.finding.hops = body_cache.build_flow_bodies(
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
    cost_finding: C,
    mut render_page: R,
) -> Result<(Vec<page_cache::CachedPage>, u64)>
where
    C: Fn(usize, &TaintAnalysisRenderFinding) -> u64,
    R: FnMut(&[usize], &paging::PageInfo, &paging::PagingConfig) -> Result<()>,
{
    let indexed: Vec<usize> = (0..report.findings.len()).collect();
    let cost = |finding_index: &usize| cost_finding(*finding_index, &report.findings[*finding_index]);
    let (_, current_info) = paging::paginate(
        &indexed,
        paging_cfg,
        "security/taint-analysis",
        filters_hash,
        cost,
    )?;
    let current_page = current_info.page_number;
    let mut pages = Vec::new();
    let page_numbers = page_cache::requested_page_window(current_page, current_info.total_pages);
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
            total_pages: info.total_pages,
            cursor: info.cursor,
            text,
        });
    }
    Ok((pages, current_page))
}

fn build_taint_json_pages(
    render_workspace: Option<&bonsai_sdk::Workspace>,
    report: &TaintAnalysisRenderReport,
    paging_cfg: &paging::PagingConfig,
    filters_hash: u64,
) -> Result<(Vec<page_cache::CachedPage>, u64)> {
    // JSON and text expose the same evidence. Compute exact serialized row
    // costs one finding at a time so pagination remains correct without
    // retaining every duplicated source body in memory.
    let mut body_cache = render_workspace.map(bonsai_sdk::FlowBodyCache::new);
    let mut row_costs = Vec::with_capacity(report.findings.len());
    for (index, original) in report.findings.iter().enumerate() {
        let mut item = original.clone();
        if let Some(cache) = body_cache.as_mut() {
            attach_flow_evidence_to_render_finding(cache, &mut item);
        }
        let row = taint_json_row(&item, index)?;
        row_costs.push(serde_json::to_vec(&row)?.len() as u64 + paging::TABLE_ROW_CHROME_BYTES);
    }
    build_taint_pages(
        report,
        paging_cfg,
        filters_hash,
        |index, _finding| row_costs[index],
        |paged_idx, info, page_cfg| {
            render_taint_json_page(render_workspace, report, paged_idx, info, page_cfg)
        },
    )
}

fn render_taint_json_page(
    render_workspace: Option<&bonsai_sdk::Workspace>,
    report: &TaintAnalysisRenderReport,
    paged_idx: &[usize],
    info: &paging::PageInfo,
    _paging_cfg: &paging::PagingConfig,
) -> Result<()> {
    let mut body_cache = render_workspace.map(bonsai_sdk::FlowBodyCache::new);
    let mut rows = Vec::with_capacity(paged_idx.len());
    for index in paged_idx {
        let mut item = report.findings[*index].clone();
        if let Some(cache) = body_cache.as_mut() {
            attach_flow_evidence_to_render_finding(cache, &mut item);
        }
        rows.push(taint_json_row(&item, *index)?);
    }
    // Security JSON is always an envelope, including `--all`. A bare empty
    // array cannot distinguish a proven clean scan from parser/resolution
    // failure, which is unsafe for automation.
    let mut analysis_incomplete_reasons = report.analysis_incomplete_reasons.clone();
    if !report.analysis_complete && analysis_incomplete_reasons.is_empty() {
        analysis_incomplete_reasons.push("taint-analysis incomplete: unknown reason".to_string());
    }
    let result_incomplete_reasons = paged_json_incomplete_reasons("security/taint-analysis", info);
    let mut wrapped = serde_json::json!({
        "analysis_complete": report.analysis_complete,
        "analysis_incomplete_reasons": analysis_incomplete_reasons,
        "result_complete": result_incomplete_reasons.is_empty(),
        "result_incomplete_reasons": result_incomplete_reasons,
        "runtime_disabled_rules": report.runtime_disabled_rules,
        "summary": compact_taint_summary(&report.summary),
        "rows": rows,
        "page": page_info_to_json(info),
    });
    if let (Some(diff), Some(fields)) = (report.baseline.as_ref(), wrapped.as_object_mut()) {
        fields.insert("baseline".to_string(), serde_json::to_value(diff)?);
    }
    crate::output::emit_json_document(&wrapped)?;
    Ok(())
}

fn taint_json_row(item: &TaintAnalysisRenderFinding, index: usize) -> Result<serde_json::Value> {
    let mut row = serde_json::to_value(item)?;
    if let (Some(flow), Some(fields)) = (flow_from_finding_hops(&item.finding, index), row.as_object_mut()) {
        fields.insert("flow".to_string(), serde_json::to_value(flow)?);
    }
    Ok(row)
}

fn build_taint_text_pages(
    workspace: &Path,
    render_workspace: Option<&bonsai_sdk::Workspace>,
    pack: &Rulepack,
    report: &TaintAnalysisRenderReport,
    paging_cfg: &paging::PagingConfig,
    filters_hash: u64,
) -> Result<(Vec<page_cache::CachedPage>, u64)> {
    let budget = paging_cfg.effective_budget();
    let page_payload_budget_bytes = budget
        .map(|tokens| tokens.saturating_mul(paging::BYTES_PER_TOKEN).saturating_mul(65) / 100)
        .unwrap_or(u64::MAX / 8)
        .max(2_048);

    // A security flow is one semantic row. Keep all of its numbered steps in
    // one display block whenever that row fits the page payload. Fragment only
    // genuinely oversized rows so context pagination remains exact without
    // turning an ordinary flow into artificial `FLOW 1/2` sections.
    let unit_target_bytes = page_payload_budget_bytes;

    let units = build_taint_text_units(render_workspace, report, unit_target_bytes)?;
    let page_bounds = taint_text_page_bounds(&units, page_payload_budget_bytes);
    let current_page = resolve_taint_text_page(&page_bounds, paging_cfg, filters_hash)?;
    let page_numbers: Vec<u64> = page_cache::requested_page_window(current_page, page_bounds.len() as u64)
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
        let estimated_payload_bytes: u64 = units[start..end].iter().map(|unit| unit.estimated_bytes).sum();
        let shown_flows = units[start..end]
            .iter()
            .map(|unit| unit.finding_idx)
            .collect::<ahash::AHashSet<_>>()
            .len() as u64;
        let mut info = paging::PageInfo {
            page_number,
            total_pages: page_bounds.len() as u64,
            page_size: shown_flows,
            shown_rows: shown_flows,
            total_rows: report.findings.len() as u64,
            budget,
            tokens_used: paging::bytes_to_tokens(estimated_payload_bytes),
            cursor: cursor.clone(),
            next_cursor,
            is_last: page_idx + 1 >= page_bounds.len(),
            start_offset: start as u64,
            total_tokens_uncapped: units
                .iter()
                .map(|unit| paging::bytes_to_tokens(unit.estimated_bytes))
                .sum(),
        };
        let body = page_cache::capture(|| {
            render_taint_analysis_text_body(workspace, pack, report, &units[start..end])?;
            if let Some(diff) = report.baseline.as_ref() {
                render_baseline_summary_text(diff);
            }
            Ok(())
        })?;
        info.tokens_used = paging::bytes_to_tokens(body.len() as u64);
        let text = page_cache::capture(|| {
            cli_print!("{body}");
            render_paging_footer(&info, "bonsai-ninja security <workspace> taint-analysis");
            Ok(())
        })?;
        pages.push(page_cache::CachedPage {
            number: page_number,
            total_pages: page_bounds.len() as u64,
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
    finding: std::sync::Arc<TaintAnalysisRenderFinding>,
    finding_idx: usize,
    flow: Option<crate::commands::InspectFlowRendered>,
    chunk_idx: usize,
    total_chunks: usize,
    estimated_bytes: u64,
}

fn build_taint_text_units(
    render_workspace: Option<&bonsai_sdk::Workspace>,
    report: &TaintAnalysisRenderReport,
    unit_target_bytes: u64,
) -> Result<Vec<TaintTextUnit>> {
    let mut units = Vec::new();
    let mut body_cache = render_workspace.map(bonsai_sdk::FlowBodyCache::new);
    for (finding_idx, original) in report.findings.iter().enumerate() {
        let mut item = original.clone();
        if let Some(cache) = body_cache.as_mut() {
            attach_flow_evidence_to_render_finding(cache, &mut item);
        }
        let item = std::sync::Arc::new(item);
        match flow_from_finding_hops(&item.finding, finding_idx) {
            Some(flow) => {
                let chunks = split_security_flow_for_context(&flow, unit_target_bytes);
                let total_chunks = chunks.len().max(1);
                for (chunk_idx, chunk) in chunks.into_iter().enumerate() {
                    let estimated_bytes = taint_text_unit_estimated_bytes(&item, Some(&chunk));
                    units.push(TaintTextUnit {
                        finding: item.clone(),
                        finding_idx,
                        flow: Some(chunk),
                        chunk_idx,
                        total_chunks,
                        estimated_bytes,
                    });
                }
            }
            None => {
                let estimated_bytes = taint_text_unit_estimated_bytes(&item, None);
                units.push(TaintTextUnit {
                    finding: item,
                    finding_idx,
                    flow: None,
                    chunk_idx: 0,
                    total_chunks: 1,
                    estimated_bytes,
                });
            }
        }
    }
    Ok(units)
}

fn taint_text_unit_estimated_bytes(
    item: &TaintAnalysisRenderFinding,
    flow: Option<&crate::commands::InspectFlowRendered>,
) -> u64 {
    let finding = &item.finding.finding;
    let metadata = finding.finding_id.len()
        + finding.source.rule_id.len()
        + finding.sink.rule_id.len()
        + finding.source.file.len()
        + finding.sink.file.len()
        + finding.source.text.len().min(256)
        + finding.sink.text.len().min(256);
    flow.map_or_else(
        || {
            taint_json_cost_bytes(item)
                .saturating_add(metadata as u64)
                .saturating_add(8_192)
        },
        |flow| {
            flow.functions
                .iter()
                .map(security_function_cost_bytes)
                .sum::<u64>()
                .saturating_add(metadata as u64)
                .saturating_add(2_048)
        },
    )
}

fn render_taint_analysis_text_body(
    workspace: &Path,
    pack: &Rulepack,
    report: &TaintAnalysisRenderReport,
    units: &[TaintTextUnit],
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
        render_taint_analysis_text_unit(
            workspace,
            pack,
            &unit.finding,
            unit.finding_idx,
            unit.flow.as_ref(),
            unit.chunk_idx,
            unit.total_chunks,
        )?;
    }
    Ok(())
}

fn render_taint_analysis_report_heading(summary: &TaintAnalysisSummary) {
    let u = ui();
    let severity_filter = summary
        .severity_floor
        .as_deref()
        .map(|severity| format!(" · severity >= {severity}"))
        .unwrap_or_default();
    let trust_filter = summary
        .view
        .as_ref()
        .and_then(|view| view.trust.as_deref())
        .map(|trust| format!(" · trust {trust}"))
        .unwrap_or_default();
    cli_println!(
        "{}",
        u.result_heading(
            "security taint-analysis",
            summary.total_findings as u64,
            "finding",
            "findings"
        )
    );
    let severities = ["critical", "high", "medium", "low", "info"]
        .into_iter()
        .filter_map(|severity| {
            let count = summary.severity_counts.get(severity).copied().unwrap_or(0);
            (count > 0).then_some(format!("{} {count}", u.severity(severity)))
        })
        .collect::<Vec<_>>();
    if !severities.is_empty() {
        cli_println!("  {}", severities.join(" · "));
    }
    cli_println!(
        "{}",
        u.dim(&format!(
            "rules: {} sources · {} sinks · {} sanitizers{}{}",
            summary.source_rule_count,
            summary.sink_rule_count,
            summary.sanitizer_rule_count,
            severity_filter,
            trust_filter,
        ))
    );
    render_taint_view_hidden_line(summary);
}

/// One line naming the complete findings a view hides and how to reveal
/// them. Silent when the view hides nothing.
fn render_taint_view_hidden_line(summary: &TaintAnalysisSummary) {
    let Some(view) = summary.view.as_ref().filter(|view| view.hidden_total > 0) else {
        return;
    };
    let u = ui();
    let breakdown = view
        .hidden
        .iter()
        .map(|(reason, count)| format!("{reason} {count}"))
        .collect::<Vec<_>>()
        .join(", ");
    cli_println!(
        "{}",
        u.warn(&format!(
            "view hides {} of {} complete finding(s) ({breakdown}){}",
            view.hidden_total,
            view.complete_findings,
            view.widen_hint()
        ))
    );
}

fn render_taint_analysis_text_unit(
    workspace: &Path,
    pack: &Rulepack,
    item: &TaintAnalysisRenderFinding,
    finding_idx: usize,
    flow: Option<&crate::commands::InspectFlowRendered>,
    chunk_idx: usize,
    total_chunks: usize,
) -> Result<()> {
    let u = ui();
    if chunk_idx == 0 {
        render_finding_security_header(u, workspace, finding_idx + 1, &item.finding, pack);
        if item.baseline_status.as_deref() == Some("new") {
            cli_println!("  {}", u.warn("[NEW since baseline]"));
        }
    } else {
        render_finding_flow_part_header(u, finding_idx + 1, &item.finding, chunk_idx + 1, total_chunks);
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
        render_finding_block_compact(u, workspace, &item.finding, pack);
    }
    Ok(())
}

fn render_finding_flow_part_header(
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
        u.annotation(&format!("FINDING {idx} · TAINT FLOW PART {chunk}/{total_chunks}")),
        u.name(vuln_class),
        severity_cell(u, &sev),
        u.dim(&f.finding_id),
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
            let cost = units[end].estimated_bytes;
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
            next.annotation = Some(format!("source line part {}", part + 1));
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
    pack: &Rulepack,
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
            let presentation = taint_finding_presentation(&finding, pack);
            TaintAnalysisRenderFinding {
                finding,
                presentation,
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

fn taint_finding_presentation(
    combined: &CombinedFindingWithChain,
    pack: &Rulepack,
) -> TaintFindingPresentation {
    let finding = &combined.finding;
    let mut rules = BTreeMap::new();
    let mut add_rule = |matched: &FindingMatch| {
        let Some(rule) = pack.find_rule_by_id(&matched.rule_id) else {
            return;
        };
        rules
            .entry(matched.rule_id.clone())
            .or_insert_with(|| TaintRulePresentation {
                title: rule.title.clone(),
                description: rule.description.trim().to_string(),
                tag: rule.tag.clone(),
                severity: rule.severity,
                trust: rule.trust,
                category: rule.category.clone(),
                cwe: rule.cwe.clone(),
                owasp: rule.owasp.clone(),
                packages: rule.packages.clone(),
                frameworks: rule.frameworks.clone(),
            });
    };

    add_rule(&finding.source);
    for source in &combined.additional_sources {
        add_rule(source);
    }
    for flow in &finding.alternate_flows {
        add_rule(&flow.source);
        for transform in &flow.taint_transforms_seen {
            add_rule(transform);
        }
        for sanitizer in &flow.sanitizers_seen {
            add_rule(sanitizer);
        }
    }
    for transform in &finding.taint_transforms_seen {
        add_rule(transform);
    }
    for sanitizer in &finding.sanitizers_seen {
        add_rule(sanitizer);
    }
    add_rule(&finding.sink);
    for sink in &combined.additional_sinks {
        add_rule(sink);
    }

    TaintFindingPresentation {
        summary: synth_summary(combined, pack),
        packages: combined_sink_metadata(combined, pack, |rule| &rule.packages),
        frameworks: combined_sink_metadata(combined, pack, |rule| &rule.frameworks),
        rules,
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
        crate::output::emit_json_document(&out)?;
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
        view: None,
        source_rule_count,
        sink_rule_count,
        sanitizer_rule_count,
        severity_floor: None,
        severity_counts: BTreeMap::new(),
        status_counts: BTreeMap::new(),
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
fn filter_taint_render_report(
    report: &TaintAnalysisRenderReport,
    render_workspace: Option<&bonsai_sdk::Workspace>,
    view: &TaintViewFilters,
) -> Result<TaintAnalysisRenderReport> {
    let secondary = crate::filter::active();
    let mut body_cache = if secondary.is_active() {
        render_workspace.map(bonsai_sdk::FlowBodyCache::new)
    } else {
        None
    };
    let mut findings = Vec::new();
    let mut hidden: BTreeMap<String, usize> = BTreeMap::new();
    for original in &report.findings {
        if let Some(reason) = view.reject_reason(&original.finding) {
            *hidden.entry(reason.to_string()).or_insert(0) += 1;
            continue;
        }
        let mut finding = original.clone();
        if let Some(cache) = body_cache.as_mut() {
            attach_flow_evidence_to_render_finding(cache, &mut finding);
        }
        if secondary.matches_value(&finding.finding) {
            findings.push(finding);
        } else {
            *hidden.entry("text".to_string()).or_insert(0) += 1;
        }
    }
    ensure_selected_taint_view_exists(findings.len(), view)?;
    let mut summary = summarize_taint_findings(
        findings.iter().map(|rf| &rf.finding),
        findings.len(),
        report.summary.source_rule_count,
        report.summary.sink_rule_count,
        report.summary.sanitizer_rule_count,
        report.analysis_complete,
        report.analysis_incomplete_reasons.clone(),
    );
    summary.severity_floor = view.severity.map(|severity| severity.as_str().to_string());
    let hidden_total: usize = hidden.values().sum();
    if view.trust.is_some() || hidden_total > 0 {
        let mut widen: Vec<String> = Vec::new();
        for reason in hidden.keys() {
            for flag in TaintViewFilters::widen_flags(reason) {
                if !widen.iter().any(|existing| existing == flag) {
                    widen.push((*flag).to_string());
                }
            }
        }
        summary.view = Some(TaintViewSummary {
            trust: view.trust.clone(),
            complete_findings: report.findings.len(),
            hidden,
            hidden_total,
            widen,
        });
    }
    Ok(TaintAnalysisRenderReport {
        summary,
        findings,
        analysis_complete: report.analysis_complete,
        analysis_incomplete_reasons: report.analysis_incomplete_reasons.clone(),
        runtime_disabled_rules: report.runtime_disabled_rules.clone(),
        bulk_flow_evidence: report.bulk_flow_evidence,
        baseline: None,
    })
}

fn ensure_selected_taint_view_exists(finding_count: usize, view: &TaintViewFilters) -> Result<()> {
    if finding_count != 0 || !view.has_identity_selector() {
        return Ok(());
    }
    let (kind, id) = if let Some(id) = view.finding.as_deref() {
        ("finding", id)
    } else if let Some(id) = view.flow.as_deref() {
        ("security flow", id)
    } else if let Some(id) = view.group.as_deref() {
        ("security flow group", id)
    } else {
        return Ok(());
    };
    Err(MissingStableId {
        kind,
        id: id.to_string(),
    }
    .into())
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
            body_bytes: 0,
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
        plan: None,
        flow_number,
        flow_label,
        flow_id: finding
            .finding
            .representative_flow_id
            .clone()
            .unwrap_or_else(|| finding.finding.finding_id.clone()),
        chain_display: chain.join(" -> "),
        chain,
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

fn flow_from_sink_lineage_hops(
    lineage: &SinkAnalysisFlow,
    sink: &FindingMatch,
    hops: Vec<bonsai_sdk::FlowFunctionBody>,
    idx: usize,
) -> Option<crate::commands::InspectFlowRendered> {
    if hops.is_empty() {
        return None;
    }
    let functions = hops
        .into_iter()
        .map(|hop| crate::commands::inspect::InspectFunctionRendered {
            body_bytes: 0,
            module_path: hop.file,
            owners: Vec::new(),
            name: hop.function.clone(),
            signature: hop.function,
            start_line: hop.start_line,
            end_line: hop.lines.last().map_or(hop.start_line, |line| line.n),
            lines: hop
                .lines
                .into_iter()
                .map(|line| crate::commands::inspect::InspectLine {
                    line_no: line.n,
                    text: line.text,
                    step: None,
                    annotation: None,
                })
                .collect(),
        })
        .collect();
    let mut rendered = crate::commands::InspectFlowRendered {
        plan: None,
        flow_number: u32::try_from(idx + 1).unwrap_or(u32::MAX),
        flow_label: (idx + 1).to_string(),
        flow_id: lineage.flow_id.clone(),
        chain: lineage.chain_names.clone(),
        chain_display: lineage.chain_names.join(" -> "),
        functions,
    };
    annotate_sink_lineage_flow(&mut rendered, &lineage.taint_path, sink);
    Some(rendered)
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
    if let Some(severity) = summary.severity_floor.as_deref() {
        cli_println!("{}", u.dim(&format!("filter: sink severity >= {severity}")));
    }
    if let Some(trust) = summary.view.as_ref().and_then(|view| view.trust.as_deref()) {
        cli_println!("{}", u.dim(&format!("filter: source trust {trust}")));
    }
    render_taint_view_hidden_line(summary);
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
        let label = if key_header == "severity" {
            u.severity(key)
        } else {
            u.name(key)
        };
        table.add_row(vec![Cell::new(label), Cell::new(*count)]);
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
        "severity_floor": summary.severity_floor,
        "severity_counts": summary.severity_counts,
        "status_counts": summary.status_counts,
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

// ---- sink-analysis — backward lineage into every selected sink ----

#[derive(Clone, Serialize)]
struct SinkAnalysisPresentationFlow {
    flow_id: String,
    origin_function: String,
    origin_file: String,
    origin_line: u32,
    chain_names: Vec<String>,
    taint_path: Vec<TaintPropagationStep>,
    endpoint_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow: Option<crate::commands::InspectFlowRendered>,
}

#[derive(Clone, Serialize)]
struct SinkAnalysisPresentationCandidate {
    sink_number: usize,
    sink: FindingMatch,
    upstream_flows: Vec<SinkAnalysisPresentationFlow>,
    security_source_flows: Vec<CombinedFindingWithChain>,
}

fn render_sink_analysis_candidates(
    ws: &bonsai_sdk::Workspace,
    candidates: &[SinkAnalysisCandidate],
    start_offset: u64,
) -> Vec<SinkAnalysisPresentationCandidate> {
    let mut body_cache = bonsai_sdk::FlowBodyCache::new(ws);
    candidates
        .iter()
        .enumerate()
        .map(|(candidate_index, candidate)| {
            let sink_number = usize::try_from(start_offset)
                .unwrap_or(usize::MAX)
                .saturating_add(candidate_index)
                .saturating_add(1);
            let upstream_flows = candidate
                .upstream_flows
                .iter()
                .enumerate()
                .map(|(flow_index, lineage)| {
                    let hops = body_cache.build_lineage_bodies(
                        &lineage.chain_funcs,
                        None,
                        &lineage.taint_path,
                        bonsai_sdk::SecurityFlowRole::Sink,
                    );
                    SinkAnalysisPresentationFlow {
                        flow_id: lineage.flow_id.clone(),
                        origin_function: lineage.origin_function.clone(),
                        origin_file: lineage.origin_file.clone(),
                        origin_line: lineage.origin_line,
                        chain_names: lineage.chain_names.clone(),
                        taint_path: lineage.taint_path.clone(),
                        endpoint_only: lineage.endpoint_only,
                        flow: flow_from_sink_lineage_hops(lineage, &candidate.sink, hops, flow_index),
                    }
                })
                .collect();
            SinkAnalysisPresentationCandidate {
                sink_number,
                sink: candidate.sink.clone(),
                upstream_flows,
                security_source_flows: candidate.security_source_flows.clone(),
            }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)] // Mirrors the explicit CLI/SDK option surface.
fn cmd_sink_analysis(
    workspace: &Path,
    pack: &Rulepack,
    rules_dir: &Path,
    source: Option<String>,
    trust: Option<String>,
    category: Option<String>,
    sink: Option<String>,
    severity: Option<Severity>,
    tag: Option<String>,
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
    // Analysis scope is the workspace shape plus the sink set. Lineage is
    // compiled per sink, and a complete every-sink object over a
    // multi-million-line workspace runs for a quarter hour, so `--sink`
    // chooses which sinks are compiled; severity, tag, and every source
    // selector are views over that cached report, which carries the
    // security-source proofs for every loaded source rule.
    let files_filter = files.join(",");
    let exclude_files_filter = exclude_files.join(",");
    let analysis_hash = filter_signature(&[
        ("kind", "sink-analysis"),
        ("sink", sink.as_deref().unwrap_or("")),
        ("files", &files_filter),
        ("exclude_files", &exclude_files_filter),
        ("exclude_tests", if exclude_tests { "1" } else { "0" }),
        ("inferred_sources", if inferred_sources { "1" } else { "0" }),
    ]);
    let view = TaintViewFilters::compile(
        pack,
        source.as_deref(),
        None,
        None,
        None,
        trust.clone(),
        category.clone(),
        sink.as_deref(),
        severity,
        tag.clone(),
        true,
        true,
    )?;
    let cached: Option<SinkAnalysisReportCache> =
        page_cache::read_keyed_payload(workspace, analysis_hash, SINK_ANALYSIS_CACHE_KIND)?;
    let report = if let Some(cached) = cached {
        let render_progress = ScopedProgress::new("reusing cached sink-analysis report");
        let report = bonsai_sdk::SinkAnalysisReport {
            candidates: cached
                .candidates
                .into_iter()
                .map(SinkAnalysisCandidate::from)
                .collect(),
            source_rule_count: cached.source_rule_count,
            sink_rule_count: cached.sink_rule_count,
            sanitizer_rule_count: cached.sanitizer_rule_count,
            analysis_complete: cached.analysis_complete,
            analysis_incomplete_reasons: cached.analysis_incomplete_reasons,
            runtime_disabled_rules: cached.runtime_disabled_rules,
        };
        render_progress.finish();
        report
    } else {
        let mut analysis_progress = SecurityAnalysisProgress::new();
        let report = project.security().sink_analysis_with_phase_progress(
            SinkAnalysisOptions {
                source: None,
                trust: None,
                category: None,
                sink: sink.clone(),
                severity: None,
                tag: None,
                files: files.clone(),
                exclude_files: exclude_files.clone(),
                exclude_tests,
                include_inferred_sources: inferred_sources,
                include_security_source_flows: true,
            },
            |event| analysis_progress.handle(event),
        )?;
        page_cache::save_keyed_payload(
            workspace,
            analysis_hash,
            SINK_ANALYSIS_CACHE_KIND,
            &SinkAnalysisReportCache {
                candidates: report
                    .candidates
                    .iter()
                    .map(SinkAnalysisCandidateCache::from)
                    .collect(),
                source_rule_count: report.source_rule_count,
                sink_rule_count: report.sink_rule_count,
                sanitizer_rule_count: report.sanitizer_rule_count,
                analysis_complete: report.analysis_complete,
                analysis_incomplete_reasons: report.analysis_incomplete_reasons.clone(),
                runtime_disabled_rules: report.runtime_disabled_rules.clone(),
            },
        )?;
        report
    };
    let mut candidates = report.candidates;
    candidates.retain_mut(|candidate| view.retain_sink_candidate(candidate));
    let total_candidates = candidates.len();
    let total_upstream_flows = candidates
        .iter()
        .flat_map(|candidate| candidate.upstream_flows.iter())
        .count();
    let total_security_source_flows = candidates
        .iter()
        .flat_map(|candidate| candidate.security_source_flows.iter())
        .map(|flow| 1usize.saturating_add(flow.finding.alternate_flows.len()))
        .sum::<usize>();
    let source_rule_count = report.source_rule_count;
    let sink_rule_count = report.sink_rule_count;
    let sanitizer_rule_count = report.sanitizer_rule_count;
    let report_analysis_complete = report.analysis_complete;
    let report_analysis_incomplete_reasons = report.analysis_incomplete_reasons;
    let runtime_disabled_rules = report.runtime_disabled_rules;
    // Secondary filtering is a view over the complete hydrated sink object:
    // sink code, upstream lineage hops with their source lines, and any
    // security-source proof. The engine candidate stores compact ids and
    // spans, so hydrate each candidate first, keep the whole candidate when
    // any field matches, and let paging render the selected set normally.
    let secondary = crate::filter::active();
    if secondary.is_active() {
        candidates.retain(|candidate| {
            render_sink_analysis_candidates(ws, std::slice::from_ref(candidate), 0)
                .first()
                .is_some_and(|rendered| secondary.matches_value(rendered))
        });
    }
    let secondary_hash = format!("{:016x}", secondary.signature());
    let filters_hash = filter_signature(&[
        ("kind", "sink-analysis"),
        ("source", source.as_deref().unwrap_or("")),
        ("trust", trust.as_deref().unwrap_or("")),
        ("category", category.as_deref().unwrap_or("")),
        ("sink", sink.as_deref().unwrap_or("")),
        ("severity", severity.map(Severity::as_str).unwrap_or("")),
        ("tag", tag.as_deref().unwrap_or("")),
        ("secondary", secondary_hash.as_str()),
    ]);
    // The text render hydrates the body of every chain function of every
    // upstream route and one excerpt per hop of every security proof; the
    // JSON size alone does not cover those source lines, so the estimate
    // adds the same per-function body costs the taint renderer uses.
    let body_costs = function_costs_for_paths(
        ws,
        candidates
            .iter()
            .flat_map(|candidate| candidate.upstream_flows.iter())
            .flat_map(|flow| flow.chain_funcs.iter().copied()),
        false,
    );
    let cost = |candidate: &SinkAnalysisCandidate| {
        let json = serde_json::to_vec(candidate)
            .map(|bytes| bytes.len() as u64)
            .unwrap_or(2_048);
        let upstream: u64 = candidate
            .upstream_flows
            .iter()
            .map(|flow| {
                flow.chain_funcs
                    .iter()
                    .map(|func| body_costs.get(func).copied().unwrap_or(512))
                    .sum::<u64>()
                    + 320
                    + taint_path_cost_bytes(&flow.taint_path)
            })
            .sum();
        let proofs: u64 = candidate
            .security_source_flows
            .iter()
            .map(|flow| {
                let hops = flow.finding.hops.len().max(flow.finding.taint_path.len()).max(1) as u64;
                hops * 1_200 + 600 + taint_path_cost_bytes(&flow.finding.taint_path)
            })
            .sum();
        json.saturating_add(1_024)
            .saturating_add(upstream)
            .saturating_add(proofs)
    };

    page_cache::emit_paged_text_prefiltered(
        workspace,
        &candidates,
        &paging_cfg,
        "security/sink-analysis",
        filters_hash,
        cost,
        |paged, info, _cfg| match format {
            BrowseFormat::Json => {
                let rendered = render_sink_analysis_candidates(ws, paged, info.start_offset);
                let result_complete = info.page_number == 1 && info.is_last;
                let wrapped = serde_json::json!({
                    "analysis_complete": report_analysis_complete,
                    "analysis_incomplete_reasons": report_analysis_incomplete_reasons,
                    "result_complete": result_complete,
                    "result_incomplete_reasons": if result_complete {
                        Vec::<String>::new()
                    } else {
                        paged_json_incomplete_reasons("security/sink-analysis", info)
                    },
                    "runtime_disabled_rules": &runtime_disabled_rules,
                    "rows": rendered,
                    "summary": {
                        "sink_count": total_candidates,
                        "upstream_flow_count": total_upstream_flows,
                        "security_source_flow_count": total_security_source_flows,
                        "source_rule_count": source_rule_count,
                        "sink_rule_count": sink_rule_count,
                        "sanitizer_rule_count": sanitizer_rule_count,
                        "severity_floor": severity.map(Severity::as_str),
                    },
                    "page": page_info_to_json(info),
                });
                crate::output::emit_json_document(&wrapped)?;
                Ok(())
            }
            BrowseFormat::Text => {
                let rendered = render_sink_analysis_candidates(ws, paged, info.start_offset);
                render_sink_analysis_text_page(
                    workspace,
                    pack,
                    &rendered,
                    info,
                    total_candidates,
                    total_upstream_flows,
                    total_security_source_flows,
                    source_rule_count,
                    sink_rule_count,
                    sanitizer_rule_count,
                    severity,
                    report_analysis_complete,
                    &report_analysis_incomplete_reasons,
                    &runtime_disabled_rules,
                )
            }
        },
    )
}

#[allow(clippy::too_many_arguments)] // Render context stays explicit for completeness metadata.
fn render_sink_analysis_text_page(
    workspace: &Path,
    pack: &Rulepack,
    candidates: &[SinkAnalysisPresentationCandidate],
    info: &paging::PageInfo,
    total_candidates: usize,
    total_upstream_flows: usize,
    total_security_source_flows: usize,
    source_rule_count: usize,
    sink_rule_count: usize,
    sanitizer_rule_count: usize,
    severity_floor: Option<Severity>,
    report_analysis_complete: bool,
    report_analysis_incomplete_reasons: &[String],
    runtime_disabled_rules: &[RuntimeDisabledRule],
) -> Result<()> {
    let u = ui();
    let severity_filter = severity_floor
        .map(|severity| format!(" · severity >= {}", severity.as_str()))
        .unwrap_or_default();
    let source_proof_summary = format!("{total_security_source_flows} security-source proof(s)");
    cli_println!(
        "{}",
        u.dim(&format!(
            "security sink-analysis — {total_candidates} sink(s) · {total_upstream_flows} upstream flow(s) · \
             {source_proof_summary} · \
             {source_rule_count} source rule(s) · {sink_rule_count} sink rule(s) · \
             {sanitizer_rule_count} sanitizer rule(s) loaded{severity_filter}"
        ))
    );
    if report_analysis_complete {
        cli_println!("{}", u.dim("analysis: complete"));
    } else {
        let reason = if report_analysis_incomplete_reasons.is_empty() {
            "unknown semantic coverage gap".to_string()
        } else {
            report_analysis_incomplete_reasons.join(", ")
        };
        cli_println!("{}", u.warn(&format!("analysis incomplete — {reason}")));
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

    for candidate in candidates {
        let sink_number = candidate.sink_number;
        let severity = candidate
            .sink
            .severity
            .map_or_else(|| "-".to_string(), |value| value.as_str().to_string());
        cli_println!();
        cli_println!("{}", u.ruler('═', 70));
        cli_println!(
            "{} · {} · {}  {}",
            u.annotation(&format!("SINK {sink_number}")),
            u.name(candidate.sink.tag.as_deref().unwrap_or("sink")),
            severity_cell(u, &severity),
            u.dim(&candidate.sink.rule_id),
        );
        render_finding_side(u, workspace, FindingSide::Sink, &candidate.sink, pack);
        for (flow_index, flow) in candidate.upstream_flows.iter().enumerate() {
            cli_println!();
            cli_println!("{}", u.ruler('─', 70));
            let reverse_chain = flow
                .chain_names
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join(" ← ");
            cli_println!(
                "  {} {}  {}",
                u.annotation(&format!("SINK {sink_number} · UPSTREAM FLOW {}", flow_index + 1)),
                u.dim(&flow.flow_id),
                u.dim(&reverse_chain),
            );
            cli_println!(
                "  {} {} at {}:{}{}",
                u.kind("ORIGIN:"),
                u.name(&flow.origin_function),
                flow.origin_file,
                flow.origin_line,
                if flow.endpoint_only {
                    u.dim(" · no additional upstream compiler lineage resolved")
                } else {
                    String::new()
                }
            );
            if let Some(rendered) = flow.flow.as_ref() {
                let render_opts = crate::commands::InspectRenderOptions::default();
                let mut local_seen: crate::commands::BodySet = ahash::AHashSet::new();
                let heading = format!("SINK {sink_number} · UPSTREAM FLOW");
                crate::commands::render_flow_block_with_heading(
                    u,
                    &render_opts,
                    rendered,
                    &candidate.sink.rule_id,
                    &mut local_seen,
                    &heading,
                );
            }
        }

        cli_println!();
        if candidate.security_source_flows.is_empty() {
            cli_println!(
                "  {} {}",
                u.kind("SECURITY SOURCE:"),
                u.dim("no selected security source reaches this sink; upstream compiler lineage remains shown above")
            );
        } else {
            cli_println!(
                "  {} {} proven selected-source flow(s)",
                u.kind("SECURITY SOURCES:"),
                candidate.security_source_flows.len()
            );
            for proof in &candidate.security_source_flows {
                let finding = &proof.finding;
                let status = match finding.status {
                    FindingStatus::Unsanitized => u.warn("unsanitized"),
                    FindingStatus::Sanitized => u.dim("sanitized · review for bypass"),
                    FindingStatus::WrongContext => u.warn("wrong-context sanitizer"),
                };
                let mut ids = vec![finding.finding_id.clone()];
                if let Some(flow_id) = finding.representative_flow_id.as_deref() {
                    ids.push(flow_id.to_string());
                }
                if let Some(group_id) = finding.group_id.as_deref() {
                    ids.push(group_id.to_string());
                }
                cli_println!(
                    "    {} {} · {} · {}",
                    u.name(&finding.source.rule_id),
                    u.dim(&ids.join(" ")),
                    status,
                    u.dim(&finding.chain_display.join(" → "))
                );
            }
        }
    }
    render_paging_footer(info, "bonsai-ninja security <workspace> sink-analysis");
    Ok(())
}

// ---- source-analysis — downstream taint/call map from all source seeds ----
#[derive(Serialize, Clone)]
struct CombinedSourceAnalysisFlow {
    source: FindingMatch,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    additional_sources: Vec<FindingMatch>,
    /// Row-level completeness. Every recorded lineage is emitted, so a row
    /// is complete exactly when the analysis that produced it was.
    analysis_complete: bool,
    analysis_incomplete_reasons: Vec<String>,
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
    // Analysis scope is the workspace shape only; every rule selector is a
    // view over the complete cached report.
    let files_filter = files.join(",");
    let exclude_files_filter = exclude_files.join(",");
    let analysis_hash = filter_signature(&[
        ("kind", "source-analysis"),
        ("files", &files_filter),
        ("exclude_files", &exclude_files_filter),
        ("exclude_tests", if exclude_tests { "1" } else { "0" }),
        ("inferred_sources", if inferred_sources { "1" } else { "0" }),
    ]);
    let view = TaintViewFilters::compile(
        pack,
        source.as_deref(),
        None,
        None,
        None,
        trust.clone(),
        category.clone(),
        None,
        None,
        tag.clone(),
        true,
        true,
    )?;
    let cached: Option<SourceAnalysisReportCache> =
        page_cache::read_keyed_payload(workspace, analysis_hash, SOURCE_ANALYSIS_CACHE_KIND)?;
    let report = if let Some(cached) = cached {
        let render_progress = ScopedProgress::new("reusing cached source-analysis report");
        let report = bonsai_sdk::SourceAnalysisReport {
            candidates: cached
                .candidates
                .into_iter()
                .map(CombinedSourceAnalysisCandidate::from)
                .collect(),
            source_rule_count: cached.source_rule_count,
            analysis_complete: cached.analysis_complete,
            analysis_incomplete_reasons: cached.analysis_incomplete_reasons,
            runtime_disabled_rules: cached.runtime_disabled_rules,
        };
        render_progress.finish();
        report
    } else {
        let mut analysis_progress = SecurityAnalysisProgress::new();
        let report = project.security().source_analysis_with_phase_progress(
            SourceAnalysisOptions {
                source: None,
                trust: None,
                category: None,
                tag: None,
                files: files.clone(),
                exclude_files: exclude_files.clone(),
                exclude_tests,
                include_inferred_sources: inferred_sources,
            },
            |event| analysis_progress.handle(event),
        )?;
        page_cache::save_keyed_payload(
            workspace,
            analysis_hash,
            SOURCE_ANALYSIS_CACHE_KIND,
            &SourceAnalysisReportCache {
                candidates: report
                    .candidates
                    .iter()
                    .map(SourceAnalysisCandidateCache::from)
                    .collect(),
                source_rule_count: report.source_rule_count,
                analysis_complete: report.analysis_complete,
                analysis_incomplete_reasons: report.analysis_incomplete_reasons.clone(),
                runtime_disabled_rules: report.runtime_disabled_rules.clone(),
            },
        )?;
        report
    };
    let source_rule_count = report.source_rule_count;
    let report_analysis_complete = report.analysis_complete;
    let mut report_analysis_incomplete_reasons = report.analysis_incomplete_reasons;
    let report_runtime_disabled_rules = report.runtime_disabled_rules;
    if !report_analysis_complete && report_analysis_incomplete_reasons.is_empty() {
        report_analysis_incomplete_reasons.push("source-analysis incomplete: unknown reason".to_string());
    }
    let mut candidates = report.candidates;
    candidates.retain(|candidate| view.retain_source_candidate(candidate));
    // Secondary filtering is a view over the complete hydrated flow object.
    // The engine candidate intentionally stores compact IDs/spans, so matching
    // it directly would miss source code and annotations that both text and
    // JSON render. Hydrate only when a secondary filter is active, retain the
    // corresponding canonical candidate, then let paging render/renumber the
    // selected flows normally.
    let secondary = crate::filter::active();
    if secondary.is_active() {
        candidates = candidates
            .into_iter()
            .enumerate()
            .filter_map(|(idx, candidate)| {
                render_source_analysis_candidate(
                    ws,
                    idx,
                    &candidate,
                    (report_analysis_complete, &report_analysis_incomplete_reasons),
                )
                .is_some_and(|rendered| secondary.matches_value(&rendered))
                .then_some(candidate)
            })
            .collect();
    }

    let secondary_hash = format!("{:016x}", secondary.signature());
    let filters_hash = filter_signature(&[
        ("kind", "source-analysis"),
        ("source", source.as_deref().unwrap_or("")),
        ("trust", trust.as_deref().unwrap_or("")),
        ("category", category.as_deref().unwrap_or("")),
        ("tag", tag.as_deref().unwrap_or("")),
        ("secondary", secondary_hash.as_str()),
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
            page_cache::emit_paged_text_prefiltered(
                workspace,
                &candidates,
                &paging_cfg,
                "security/source-analysis",
                filters_hash,
                cost,
                |paged, info, _cfg| {
                    let rendered = render_source_analysis_candidates(
                        ws,
                        paged,
                        info.start_offset,
                        (report_analysis_complete, &report_analysis_incomplete_reasons),
                    );
                    let result_incomplete_reasons =
                        paged_json_incomplete_reasons("security/source-analysis", info);
                    let result_complete = result_incomplete_reasons.is_empty();
                    let wrapped = serde_json::json!({
                        "analysis_complete": report_analysis_complete,
                        "analysis_incomplete_reasons": report_analysis_incomplete_reasons,
                        "result_complete": result_complete,
                        "result_incomplete_reasons": result_incomplete_reasons,
                        "runtime_disabled_rules": &report_runtime_disabled_rules,
                        "rows": rendered,
                        "summary": {
                            "source_flow_count": candidates.len(),
                            "source_rule_count": source_rule_count,
                        },
                        "page": page_info_to_json(info),
                    });
                    crate::output::emit_json_document(&wrapped)?;
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
            let page_render_progress = ScopedProgress::new("rendering source page");
            let mut cached_pages = Vec::new();
            for page_number in page_cache::requested_page_window(current_page, total_pages) {
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
                        workspace,
                        ws,
                        pack,
                        &paged,
                        &info,
                        candidates.len(),
                        source_rule_count,
                        report_analysis_complete,
                        &report_analysis_incomplete_reasons,
                        &report_runtime_disabled_rules,
                    )
                })?;
                cached_pages.push(page_cache::CachedPage {
                    number: page_number,
                    total_pages,
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
    workspace: &Path,
    ws: &bonsai_sdk::Workspace,
    pack: &Rulepack,
    candidates: &[CombinedSourceAnalysisCandidate],
    info: &paging::PageInfo,
    total_candidates: usize,
    source_rule_count: usize,
    report_analysis_complete: bool,
    report_analysis_incomplete_reasons: &[String],
    runtime_disabled_rules: &[RuntimeDisabledRule],
) -> Result<()> {
    let rendered = render_source_analysis_candidates(
        ws,
        candidates,
        info.start_offset,
        (report_analysis_complete, report_analysis_incomplete_reasons),
    );
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
    let render_opts = crate::commands::InspectRenderOptions::default();
    for item in rendered.iter() {
        let source_number = item.flow.flow_number as usize;
        render_source_analysis_header(u, workspace, source_number, item, pack);
        let mut local_seen: crate::commands::BodySet = ahash::AHashSet::new();
        let heading = format!("SOURCE {source_number} · DOWNSTREAM FLOW");
        crate::commands::render_flow_block_with_heading(
            u,
            &render_opts,
            &item.flow,
            &item.source.rule_id,
            &mut local_seen,
            &heading,
        );
    }
    render_paging_footer(info, "bonsai-ninja security <workspace> source-analysis");
    Ok(())
}

fn render_source_analysis_candidates(
    ws: &bonsai_sdk::Workspace,
    candidates: &[CombinedSourceAnalysisCandidate],
    start_offset: u64,
    completeness: (bool, &[String]),
) -> Vec<CombinedSourceAnalysisFlow> {
    candidates
        .iter()
        .enumerate()
        .filter_map(|(idx, item)| {
            let global_idx = usize::try_from(start_offset)
                .unwrap_or(usize::MAX)
                .saturating_add(idx);
            render_source_analysis_candidate(ws, global_idx, item, completeness)
        })
        .collect()
}

fn render_source_analysis_candidate(
    ws: &bonsai_sdk::Workspace,
    idx: usize,
    item: &CombinedSourceAnalysisCandidate,
    completeness: (bool, &[String]),
) -> Option<CombinedSourceAnalysisFlow> {
    let label = (idx + 1).to_string();
    let call_spans = security_flow_call_spans(ws, &item.path, &item.chain_names, &item.taint_path);
    let mut flow = crate::commands::render_flow_with_cached_call_spans(
        ws,
        &item.path,
        &call_spans,
        (idx + 1) as u32,
        &label,
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
        analysis_complete: completeness.0,
        analysis_incomplete_reasons: completeness.1.to_vec(),
        flow,
    })
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
    Sink,
}

impl SecurityFlowKind {
    fn heading(self) -> &'static str {
        match self {
            Self::Taint => "TAINT FLOW",
            Self::Source => "SOURCE FLOW",
            Self::Sink => "UPSTREAM FLOW",
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
        let marker = if let Some(storage) = &step.storage_transfer {
            format!("STORAGE: {} -> {} read {storage}", step.caller, step.callee)
        } else if is_sink {
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

fn annotate_sink_lineage_flow(
    flow: &mut crate::commands::InspectFlowRendered,
    taint_path: &[TaintPropagationStep],
    sink: &FindingMatch,
) {
    for func in &mut flow.functions {
        for line in &mut func.lines {
            line.step = None;
            line.annotation = None;
        }
    }
    let label = flow.flow_label.clone();
    let mut step_counter = 0u32;
    let mut sink_annotated = false;
    for step in taint_path {
        let is_sink = same_rendered_file(&step.file, &sink.file) && step.line == sink.line;
        sink_annotated |= is_sink;
        let marker = if let Some(storage) = &step.storage_transfer {
            format!("STORAGE: {} -> {} read {storage}", step.caller, step.callee)
        } else if is_sink {
            format!("SINK: {} {}", sink.rule_id, format_taint_args(&step.tainted_args))
        } else {
            format!(
                "UPSTREAM: {} -> {} {}",
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
            SecurityFlowKind::Sink,
            &mut step_counter,
        );
    }
    if !sink_annotated {
        add_flow_line_annotation(
            flow,
            &sink.file,
            sink.line,
            &label,
            format!("SINK: {} {}", sink.rule_id, format_sink_args(sink)),
            SecurityFlowKind::Sink,
            &mut step_counter,
        );
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
        return "(no argument attribution)".to_string();
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
        return "(no argument attribution)".to_string();
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

fn render_source_analysis_header(
    u: &Ui,
    workspace: &Path,
    idx: usize,
    item: &CombinedSourceAnalysisFlow,
    pack: &Rulepack,
) {
    let source = &item.source;
    cli_println!();
    cli_println!("{}", u.ruler('═', 70));
    cli_println!(
        "{} · {}  {}",
        u.annotation(&format!("SOURCE {idx}")),
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
    render_source_analysis_source(u, workspace, source, pack);
    for source in &item.additional_sources {
        render_source_analysis_source(u, workspace, source, pack);
    }
}

fn render_source_analysis_source(u: &Ui, workspace: &Path, source: &FindingMatch, pack: &Rulepack) {
    cli_println!();
    cli_println!("  {} {}", u.kind("SOURCE:"), u.name(&source.rule_id));
    let loc = format!(
        "{}:{}:{}",
        security_display_file(workspace, &source.file),
        source.line,
        source.column
    );
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
/// vulnerability class, the compiler-provided route and endpoint locations,
/// then labelled `SOURCE:` / `SANITIZER:` / `SINK:` blocks
/// that each read as short prose (what the input is, what the dangerous
/// operation is, why it's dangerous) plus the rule id, location, and
/// supporting taxonomy metadata (CWE, OWASP, category, packages,
/// frameworks). Goes above the taint-flow block so a reviewer sees
/// the finding *as a vulnerability* before reading the propagation.
fn render_finding_security_header(
    u: &Ui,
    workspace: &Path,
    idx: usize,
    combined: &CombinedFindingWithChain,
    pack: &Rulepack,
) {
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
    // Put the actual route and endpoints ahead of taxonomy and rule prose.
    // This is the canonical finding's route, not a new path computation.
    if !f.chain_display.is_empty() {
        for line in u.wrapped_annotation_prefixed_lines(
            "  chain: ",
            &format!("  {} ", u.label("chain:")),
            "         ",
            &f.chain_display.join(" → "),
        ) {
            cli_println!("{line}");
        }
    }
    for (label, endpoint) in [("source", &f.source), ("sink", &f.sink)] {
        cli_println!(
            "  {} {}  {}",
            u.label(&format!("{label}:")),
            u.name(&endpoint.text),
            u.path(&format!(
                "{}:{}:{}",
                security_display_file(workspace, &endpoint.file),
                endpoint.line,
                endpoint.column
            )),
        );
    }
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
    // Rule descriptions follow once per endpoint, instead of repeating the
    // same prose in both a synthesized paragraph and the evidence blocks.
    render_finding_side(u, workspace, FindingSide::Source, &f.source, pack);
    for source in &combined.additional_sources {
        render_finding_side(u, workspace, FindingSide::Source, source, pack);
    }
    for transform in &f.taint_transforms_seen {
        render_finding_side(u, workspace, FindingSide::TaintTransform, transform, pack);
    }
    for s in &f.sanitizers_seen {
        render_finding_side(u, workspace, FindingSide::Sanitizer, s, pack);
    }
    if f.sanitizers_seen.is_empty() {
        cli_println!();
        cli_println!(
            "  {}  {}",
            u.kind("SANITIZER:"),
            u.warn("none observed on this call path"),
        );
    }
    render_finding_side(u, workspace, FindingSide::Sink, &f.sink, pack);
    for sink in &combined.additional_sinks {
        render_finding_side(u, workspace, FindingSide::Sink, sink, pack);
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
fn render_finding_side(u: &Ui, workspace: &Path, side: FindingSide, m: &FindingMatch, pack: &Rulepack) {
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
    let loc = format!(
        "{}:{}:{}",
        security_display_file(workspace, &m.file),
        m.line,
        m.column
    );
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
fn render_finding_block_compact(
    u: &Ui,
    workspace: &Path,
    combined: &CombinedFindingWithChain,
    pack: &Rulepack,
) {
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
            let loc = format!("{}:{}", security_display_file(workspace, &step.file), step.line);
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
    render_site_code(u, workspace, "SOURCE", &f.source, pack);
    for source in &combined.additional_sources {
        render_site_code(u, workspace, "SOURCE", source, pack);
    }
    for transform in &f.taint_transforms_seen {
        render_site_code(u, workspace, "TAINT TRANSFORM", transform, pack);
    }
    for s in &f.sanitizers_seen {
        render_site_code(u, workspace, "SANITIZER", s, pack);
    }
    render_site_code(u, workspace, "SINK", &f.sink, pack);
    for sink in &combined.additional_sinks {
        render_site_code(u, workspace, "SINK", sink, pack);
    }
}

fn render_site_code(u: &Ui, workspace: &Path, label: &str, m: &FindingMatch, pack: &Rulepack) {
    cli_println!();
    cli_println!("{}  {}", u.kind(&format!("[{label}]")), u.name(&m.rule_id),);
    let loc = format!(
        "{}:{}:{}",
        security_display_file(workspace, &m.file),
        m.line,
        m.column
    );
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
    let global = ws.compiler_header_index();
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

fn filter_signature(pairs: &[(&str, &str)]) -> u64 {
    paging::hash_filters(pairs)
}

fn effective_limit(limit: usize, cfg: &paging::PagingConfig) -> usize {
    crate::commands::browse::effective_limit(limit, cfg)
}

fn security_display_file(workspace: &Path, file: &str) -> String {
    bonsai_common::workspace_relative_filter_path(Some(workspace), file)
}

fn severity_cell(u: &Ui, sev: &str) -> String {
    u.severity(sev)
}

fn meta_chip(u: &Ui, label: &str, value: String) -> String {
    format!("{} {}", u.dim(label), value)
}

// ---- match-table renderer (sources + sinks) ----
#[derive(Clone, Serialize)]
struct SecurityMatchPresentationRow {
    #[serde(flatten)]
    matched: SecurityMatchRow,
    location: String,
    code: String,
}

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
    compiler_workspace: &bonsai_sdk::Workspace,
    label: &str,
    matches: &[RuleMatch],
    pack: &Rulepack,
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
    show_severity: bool,
    filters_hash: u64,
) -> Result<()> {
    // The code column is the matched source line, read only for the rows a
    // page renders: reading it for every match would load every matched
    // file before pagination. The cost model uses the matched text, which
    // is that line's substance, so pagination stays a pure function of the
    // semantic rows.
    let rows = security_match_rows(pack, matches)
        .into_iter()
        .map(|matched| {
            let location = format!(
                "{}:{}:{}",
                security_display_file(workspace, &matched.file),
                matched.line,
                matched.column
            );
            SecurityMatchPresentationRow {
                matched,
                location,
                code: String::new(),
            }
        })
        .collect::<Vec<_>>();
    let with_code = |paged: &[SecurityMatchPresentationRow]| -> Vec<SecurityMatchPresentationRow> {
        paged
            .iter()
            .map(|row| {
                let code = crate::commands::browse::read_line(
                    compiler_workspace,
                    &row.matched.file,
                    row.matched.line,
                );
                let mut row = row.clone();
                row.code = if code.trim().is_empty() {
                    row.matched.text.clone()
                } else {
                    code
                };
                row
            })
            .collect()
    };
    let cost = |row: &SecurityMatchPresentationRow| {
        (row.matched.rule_id.len()
            + row.matched.language.len()
            + row.matched.file.len()
            + row.matched.text.len()
            + row.matched.text.len()
            + row.matched.enclosing_fn.as_deref().map_or(0, str::len)
            + row.matched.description.as_deref().map_or(0, str::len)
            + row.matched.packages.iter().map(String::len).sum::<usize>()
            + row.matched.frameworks.iter().map(String::len).sum::<usize>()
            + 320) as u64
            + paging::TABLE_ROW_CHROME_BYTES
    };
    let command = format!("security/{label}");

    match format {
        BrowseFormat::Json => {
            page_cache::emit_paged_text(
                workspace,
                &rows,
                &paging_cfg,
                &command,
                filters_hash,
                cost,
                |paged, info, _cfg| {
                    let result_complete = info.page_number == 1 && info.is_last;
                    let paged = with_code(paged);
                    let payload = serde_json::json!({
                        "analysis_complete": true,
                        "analysis_incomplete_reasons": [],
                        "result_complete": result_complete,
                        "result_incomplete_reasons": if result_complete {
                            Vec::<String>::new()
                        } else {
                            paged_json_incomplete_reasons(&command, info)
                        },
                        "page": page_info_to_json(info),
                        "rows": paged,
                    });
                    crate::output::emit_json_document(&payload)?;
                    Ok(())
                },
            )?;
        }
        BrowseFormat::Text => {
            page_cache::emit_paged_text(
                workspace,
                &rows,
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
                    let rows: Vec<SecurityMatchPresentationRow> = if limit_eff == 0 {
                        with_code(paged)
                    } else {
                        with_code(&paged[..limit_eff.min(paged.len())])
                    };
                    let u = ui();
                    cli_println!(
                        "{}",
                        u.dim(&format!("security {label} — {} match(es)", info.total_rows))
                    );
                    let mut headers = vec!["rule"];
                    if show_severity {
                        headers.push("severity");
                    }
                    headers.extend(["location", "in", "code", "metadata", "description"]);
                    let mut table = u.table_pinned(&headers, &["rule"]);
                    for row in &rows {
                        let matched = &row.matched;
                        let mut metadata = Vec::new();
                        if let Some(trust) = matched.trust.as_deref() {
                            metadata.push(format!("trust {trust}"));
                        }
                        if let Some(tag) = matched.tag.as_deref() {
                            metadata.push(format!("tag {tag}"));
                        }
                        if let Some(category) = matched.category.as_deref() {
                            metadata.push(format!("category {category}"));
                        }
                        if !matched.cwe.is_empty() {
                            metadata.push(matched.cwe.join(", "));
                        }
                        if !matched.packages.is_empty() {
                            metadata.push(format!("packages {}", matched.packages.join(", ")));
                        }
                        if !matched.frameworks.is_empty() {
                            metadata.push(format!("frameworks {}", matched.frameworks.join(", ")));
                        }
                        let mut cells = vec![Cell::new(u.name(&matched.rule_id))];
                        if show_severity {
                            cells.push(Cell::new(u.severity(matched.severity.as_deref().unwrap_or("-"))));
                        }
                        cells.extend([
                            Cell::new(u.path(&row.location)),
                            Cell::new(u.kind(matched.enclosing_fn.as_deref().unwrap_or("<module>"))),
                            Cell::new(u.snippet(row.code.trim(), extension_for(&matched.file))),
                            Cell::new(u.dim(&metadata.join(" · "))),
                            Cell::new(u.dim(matched.description.as_deref().unwrap_or("-"))),
                        ]);
                        table.add_row(cells);
                    }
                    cli_println!("{table}");
                    render_truncation_notice(rows.len(), truncated);
                    render_paging_footer(info, &format!("bonsai-ninja security <workspace> {label}"));
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

#[derive(Clone, Serialize)]
struct DependencyRulePresentation {
    rule_id: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    description: String,
}

#[derive(Clone, Serialize)]
struct DependencyPresentationRow {
    language: String,
    key: String,
    rule_ids: Vec<String>,
    signals: Vec<String>,
    evidence_files: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<Severity>,
    tags: Vec<String>,
    rules: Vec<DependencyRulePresentation>,
}

fn dependency_presentation_rows(rows: &[DependencyRow], pack: &Rulepack) -> Vec<DependencyPresentationRow> {
    rows.iter()
        .map(|row| {
            let rules = row
                .rule_ids
                .iter()
                .filter_map(|rule_id| pack.find_rule_by_id(rule_id))
                .map(|rule| DependencyRulePresentation {
                    rule_id: rule.id.clone(),
                    kind: rule.kind.dir_name().to_string(),
                    severity: rule.severity,
                    tag: rule.tag.clone(),
                    description: rule.description.clone(),
                })
                .collect();
            DependencyPresentationRow {
                language: row.language.clone(),
                key: row.key.clone(),
                rule_ids: row.rule_ids.clone(),
                signals: row.signals.clone(),
                evidence_files: row.evidence_files.clone(),
                severity: row.severity,
                tags: row.tags.clone(),
                rules,
            }
        })
        .collect()
}

/// `security deps` text table: one row per package, mirroring the
/// `sinks` / `sources` inventory tables. JSON carries the same rows with the
/// full per-rule role list; the table folds roles into counts by family.
fn render_dependency_table(u: &Ui, rows: &[DependencyPresentationRow]) {
    let mut table = u.table_pinned(
        &[
            "package", "lang", "severity", "roles", "signals", "evidence", "tags",
        ],
        &["package"],
    );
    for row in rows {
        let mut sources = 0usize;
        let mut sinks = 0usize;
        let mut sanitizers = 0usize;
        let mut other = 0usize;
        for rule in &row.rules {
            match rule.kind.as_str() {
                "sources" => sources += 1,
                "sinks" => sinks += 1,
                "sanitizers" => sanitizers += 1,
                _ => other += 1,
            }
        }
        let mut roles = Vec::new();
        if sources > 0 {
            roles.push(format!("{sources} source"));
        }
        if sinks > 0 {
            roles.push(format!("{sinks} sink"));
        }
        if sanitizers > 0 {
            roles.push(format!("{sanitizers} sanitizer"));
        }
        if other > 0 {
            roles.push(format!("{other} typing"));
        }
        let severity = row
            .severity
            .map_or_else(|| u.dim("-"), |severity| severity_cell(u, severity.as_str()));
        table.add_row(vec![
            Cell::new(u.name(&row.key)),
            Cell::new(u.kind(&row.language)),
            Cell::new(severity),
            Cell::new(u.dim(&roles.join(" · "))),
            Cell::new(u.dim(&row.signals.join(", "))),
            Cell::new(u.path(&row.evidence_files.join("\n"))),
            Cell::new(u.dim(&row.tags.join(", "))),
        ]);
    }
    cli_println!("{table}");
    // Rule ids are identity facts; keep each id whole on its own wrapped
    // line instead of breaking it inside a narrow table cell.
    if rows.iter().any(|row| !row.rule_ids.is_empty()) {
        cli_println!();
        cli_println!("{}", u.label("RULES"));
        for row in rows {
            if row.rule_ids.is_empty() {
                continue;
            }
            let prefix_plain = format!("  {}: ", row.key);
            let prefix_styled = format!("  {} ", u.name(&format!("{}:", row.key)));
            let continuation = " ".repeat(prefix_plain.len());
            for line in u.wrapped_dim_prefixed_lines(
                &prefix_plain,
                &prefix_styled,
                &continuation,
                &row.rule_ids.join(", "),
            ) {
                cli_println!("{line}");
            }
        }
    }
}

/// The complete taint-analysis report for `workspace` under its file scope:
/// the keyed payload `taint-analysis` already cached when present, otherwise
/// one full analysis whose report is cached for every later view.
fn complete_taint_render_report(
    workspace: &Path,
    pack: &Rulepack,
    project: &bonsai_sdk::Project,
    files: &[String],
    exclude_files: &[String],
    exclude_tests: bool,
) -> Result<TaintAnalysisRenderReport> {
    let files_filter = files.join(",");
    let exclude_files_filter = exclude_files.join(",");
    // Identical key to `cmd_taint_analysis` for the same scope, so the
    // default taint run and dependency-analysis share one payload.
    let analysis_hash = filter_signature(&[
        ("kind", "taint-analysis"),
        ("files", &files_filter),
        ("exclude_files", &exclude_files_filter),
        ("inferred_sources", "0"),
        ("exclude_tests", if exclude_tests { "1" } else { "0" }),
    ]);
    if let Some(cached) = page_cache::read_keyed_payload::<TaintAnalysisRenderReportCache>(
        workspace,
        analysis_hash,
        TAINT_RENDER_CACHE_KIND,
    )? {
        let cached = TaintAnalysisRenderReport::from(cached);
        if !(cached.findings.is_empty() && cached.summary.total_findings > 0) {
            return Ok(cached);
        }
    }
    let mut analysis_progress = SecurityAnalysisProgress::new();
    let report = project.security().taint_analysis_with_phase_progress(
        TaintAnalysisOptions {
            source: None,
            flow_id: None,
            trust: None,
            category: None,
            sink: None,
            severity: None,
            tag: None,
            files: files.to_vec(),
            exclude_files: exclude_files.to_vec(),
            include_inferred_sources: false,
            include_pattern_only: true,
            show_sanitized: true,
            exclude_tests,
            attach_flow_evidence: false,
            taint_graph_resident_cache_entries: Some(0),
        },
        |event| analysis_progress.handle(event),
    )?;
    let render_report = build_taint_render_report(report, pack, true, false);
    save_taint_payload_if_requested(workspace, analysis_hash, 0, Vec::new(), Some(&render_report));
    Ok(render_report)
}

/// True when a taint-analysis finding involves the dependency: one of its
/// source or sink rules claims the package, or one of its propagation steps
/// lands on a usage site (an import-bound call or a rule match).
fn finding_mentions_dependency(
    item: &TaintAnalysisRenderFinding,
    rule_ids: &[String],
    sites: &[bonsai_sdk::DependencyUsageSite],
) -> bool {
    let finding = &item.finding.finding;
    let claims = |rule_id: &str| rule_ids.iter().any(|claimed| claimed == rule_id);
    if claims(&finding.source.rule_id)
        || claims(&finding.sink.rule_id)
        || item
            .finding
            .additional_sources
            .iter()
            .any(|source| claims(&source.rule_id))
        || item
            .finding
            .additional_sinks
            .iter()
            .any(|sink| claims(&sink.rule_id))
        || finding
            .alternate_flows
            .iter()
            .any(|flow| claims(&flow.source.rule_id))
    {
        return true;
    }
    let same_file = |a: &str, b: &str| a == b || a.ends_with(b) || b.ends_with(a);
    finding.taint_path.iter().any(|step| {
        sites
            .iter()
            .any(|site| site.kind != "import" && site.line == step.line && same_file(&site.file, &step.file))
    })
}

// ---- dependency-analysis — where each flagged dependency is used ----
#[allow(clippy::too_many_arguments)] // stable parameter list — one field per --flag
#[allow(clippy::too_many_arguments)]
fn cmd_dependency_analysis(
    workspace: &Path,
    pack: &Rulepack,
    rules_dir: &Path,
    framework: Option<String>,
    severity: Option<String>,
    files: Vec<String>,
    exclude_files: Vec<String>,
    exclude_tests: bool,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = if !files.is_empty() || !exclude_files.is_empty() {
        open_security_project_filtered_paths(workspace, pack, rules_dir, &files, &exclude_files)?
    } else {
        open_security_project(workspace, pack, rules_dir)?
    };
    let ws = project.workspace();
    // Inventories are complete cached objects shared with the
    // sources/sinks/sanitizers views; the analysis is a projection over them.
    let inventory_options = SecurityInventoryOptions {
        files: files.clone(),
        exclude_files: exclude_files.clone(),
        ..Default::default()
    };
    let mut inventory_progress = SecurityAnalysisProgress::new();
    let matches = bonsai_sdk::DependencyInventoryMatches {
        sources: complete_inventory(
            workspace,
            &project,
            RuleKind::Source,
            "source",
            &inventory_options,
            &mut inventory_progress,
        )?,
        sinks: complete_inventory(
            workspace,
            &project,
            RuleKind::Sink,
            "sink",
            &inventory_options,
            &mut inventory_progress,
        )?,
        sanitizers: complete_inventory(
            workspace,
            &project,
            RuleKind::Sanitizer,
            "sanitizer",
            &inventory_options,
            &mut inventory_progress,
        )?,
    };
    let collect_progress = ScopedProgress::new("collecting dependency usage");
    let report = project.security().dependency_analysis_with_matches(
        bonsai_sdk::DependencyAnalysisOptions {
            inventory: DependencyInventoryOptions {
                framework: framework.clone(),
                severity: parse_severity_flag(severity.as_deref())?,
                files: files.clone(),
                exclude_files: exclude_files.clone(),
            },
        },
        matches,
    )?;
    collect_progress.finish();
    let taint =
        complete_taint_render_report(workspace, pack, &project, &files, &exclude_files, exclude_tests)?;
    // Findings are attached by identity here; their flow bodies hydrate only
    // for the rows on the rendered page (below), never for every package.
    let rows: Vec<DependencyAnalysisPresentation> = report
        .candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let mut row = dependency_analysis_presentation(ws, workspace, pack, candidate);
            row.dependency_number = index + 1;
            for item in &taint.findings {
                if !finding_mentions_dependency(item, &candidate.dependency.rule_ids, &candidate.sites) {
                    continue;
                }
                row.finding_items.push(std::sync::Arc::new(item.clone()));
            }
            Ok(row)
        })
        .collect::<Result<Vec<_>>>()?;
    let hydrate_rows =
        |paged: &[DependencyAnalysisPresentation]| -> Result<Vec<DependencyAnalysisPresentation>> {
            let mut body_cache = bonsai_sdk::FlowBodyCache::new(ws);
            paged
                .iter()
                .map(|row| {
                    let mut hydrated = row.clone();
                    hydrated.findings.clear();
                    hydrated.finding_items = row
                        .finding_items
                        .iter()
                        .enumerate()
                        .map(|(finding_idx, item)| {
                            let mut item = (**item).clone();
                            attach_flow_evidence_to_render_finding(&mut body_cache, &mut item);
                            hydrated.findings.push(taint_json_row(&item, finding_idx)?);
                            Ok(std::sync::Arc::new(item))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    Ok(hydrated)
                })
                .collect()
        };
    let total_sites: usize = rows.iter().map(|row| row.sites.len()).sum();
    let total_flows: usize = rows.iter().map(|row| row.finding_items.len()).sum();
    let taint_analysis_complete = taint.analysis_complete;
    let taint_incomplete_reasons = taint.analysis_incomplete_reasons.clone();
    let filters_hash = filter_signature(&[
        ("kind", "dependency-analysis"),
        ("framework", framework.as_deref().unwrap_or("")),
        ("severity", severity.as_deref().unwrap_or("")),
    ]);
    let cost = |row: &DependencyAnalysisPresentation| {
        let flows: u64 = row
            .finding_items
            .iter()
            .enumerate()
            .map(|(idx, item)| {
                let flow = flow_from_finding_hops(&item.finding, idx);
                taint_text_unit_estimated_bytes(item, flow.as_ref())
            })
            .sum();
        (row.sites.len() as u64)
            .saturating_mul(256)
            .saturating_add(flows)
            .saturating_add(1_024)
    };
    let analysis_complete = report.analysis_complete && taint_analysis_complete;
    let mut analysis_incomplete_reasons = report.analysis_incomplete_reasons.clone();
    analysis_incomplete_reasons.extend(taint_incomplete_reasons);
    page_cache::emit_paged_text(
        workspace,
        &rows,
        &paging_cfg,
        "security/dependency-analysis",
        filters_hash,
        cost,
        |paged, info, _cfg| match format {
            BrowseFormat::Json => {
                let paged = hydrate_rows(paged)?;
                let result_complete = info.page_number == 1 && info.is_last;
                let payload = serde_json::json!({
                    "analysis_complete": analysis_complete,
                    "analysis_incomplete_reasons": analysis_incomplete_reasons,
                    "result_complete": result_complete,
                    "result_incomplete_reasons": if result_complete {
                        Vec::<String>::new()
                    } else {
                        paged_json_incomplete_reasons("security/dependency-analysis", info)
                    },
                    "rows": paged,
                    "summary": {
                        "dependency_count": rows.len(),
                        "site_count": total_sites,
                        "taint_flow_count": total_flows,
                        "source_rule_count": taint.summary.source_rule_count,
                        "sink_rule_count": taint.summary.sink_rule_count,
                        "sanitizer_rule_count": taint.summary.sanitizer_rule_count,
                        "severity_floor": severity.as_deref(),
                    },
                    "page": page_info_to_json(info),
                });
                crate::output::emit_json_document(&payload)?;
                Ok(())
            }
            BrowseFormat::Text => {
                let u = ui();
                cli_println!(
                    "{}",
                    u.dim(&format!(
                        "security dependency-analysis — {} package(s) · {total_sites} usage site(s) · {total_flows} taint flow(s) · \
                         {} source rule(s) · {} sink rule(s) · {} sanitizer rule(s) loaded",
                        rows.len(),
                        taint.summary.source_rule_count,
                        taint.summary.sink_rule_count,
                        taint.summary.sanitizer_rule_count,
                    ))
                );
                if analysis_complete {
                    cli_println!("{}", u.dim("analysis: complete"));
                } else {
                    cli_println!(
                        "{}",
                        u.warn(&format!(
                            "analysis incomplete — {}",
                            analysis_incomplete_reasons.join(", ")
                        ))
                    );
                }
                for row in &hydrate_rows(paged)? {
                    render_dependency_analysis_block(u, workspace, pack, row)?;
                }
                render_paging_footer(info, "bonsai-ninja security <workspace> dependency-analysis");
                Ok(())
            }
        },
    )
}

#[derive(Clone, Serialize)]
struct DependencyAnalysisSitePresentation {
    kind: String,
    location: String,
    file: String,
    line: u32,
    column: u32,
    text: String,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    in_function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    via_alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<String>,
}

#[derive(Clone, Serialize)]
struct DependencyAnalysisPresentation {
    /// 1-based position in the complete report; stable across pages.
    dependency_number: usize,
    dependency: DependencyPresentationRow,
    bound_names: Vec<String>,
    sites: Vec<DependencyAnalysisSitePresentation>,
    /// The taint-analysis findings this package appears in, in the same row
    /// shape as `security taint-analysis --format json` (flow bodies included).
    findings: Vec<serde_json::Value>,
    #[serde(skip)]
    finding_items: Vec<std::sync::Arc<TaintAnalysisRenderFinding>>,
}

fn dependency_analysis_presentation(
    ws: &bonsai_sdk::Workspace,
    workspace: &Path,
    pack: &Rulepack,
    candidate: &bonsai_sdk::DependencyAnalysisCandidate,
) -> DependencyAnalysisPresentation {
    let dependency = dependency_presentation_rows(std::slice::from_ref(&candidate.dependency), pack)
        .pop()
        .expect("one presentation row per dependency");
    let sites = candidate
        .sites
        .iter()
        .map(|site| {
            let code = crate::commands::browse::read_line(ws, &site.file, site.line);
            DependencyAnalysisSitePresentation {
                kind: site.kind.clone(),
                location: format!(
                    "{}:{}:{}",
                    security_display_file(workspace, &site.file),
                    site.line,
                    site.column
                ),
                file: site.file.clone(),
                line: site.line,
                column: site.column,
                text: site.text.clone(),
                code: if code.trim().is_empty() {
                    site.text.clone()
                } else {
                    code
                },
                in_function: site.in_function.clone(),
                via_alias: site.via_alias.clone(),
                rule_id: site.rule_id.clone(),
            }
        })
        .collect();
    DependencyAnalysisPresentation {
        dependency_number: 0,
        dependency,
        bound_names: candidate.bound_names.clone(),
        sites,
        findings: Vec::new(),
        finding_items: Vec::new(),
    }
}

fn render_dependency_analysis_block(
    u: &Ui,
    workspace: &Path,
    pack: &Rulepack,
    row: &DependencyAnalysisPresentation,
) -> Result<()> {
    let dependency = &row.dependency;
    let severity = dependency
        .severity
        .map_or_else(|| "-".to_string(), |value| value.as_str().to_string());
    cli_println!();
    cli_println!("{}", u.ruler('═', 70));
    cli_println!(
        "{} · {} · {}  {}",
        u.annotation(&format!("PACKAGE {}", row.dependency_number)),
        u.name(&dependency.key),
        severity_cell(u, &severity),
        u.dim(&dependency.language),
    );
    let mut chips = Vec::new();
    if !dependency.signals.is_empty() {
        chips.push(format!("signals {}", dependency.signals.join(", ")));
    }
    if !dependency.tags.is_empty() {
        chips.push(format!("tags {}", dependency.tags.join(", ")));
    }
    if !row.bound_names.is_empty() {
        chips.push(format!("bound as {}", row.bound_names.join(", ")));
    }
    chips.push(format!("rules {}", dependency.rules.len()));
    for line in u.wrapped_dim_prefixed_lines(
        "    meta: ",
        &format!("    {} ", u.dim("meta:")),
        "          ",
        &chips.join(" · "),
    ) {
        cli_println!("{line}");
    }
    if !dependency.evidence_files.is_empty() {
        cli_println!(
            "    {} {}",
            u.label("EVIDENCE"),
            u.path(&dependency.evidence_files.join(", "))
        );
    }
    if row.sites.is_empty() {
        cli_println!(
            "    {}",
            u.dim("no import, call, reference, or rule-match site in the analyzed files")
        );
    } else {
        cli_println!("    {} ({})", u.label("USAGE SITES"), row.sites.len());
        let mut table = u.table_pinned(&["kind", "location", "in", "via", "code"], &["kind"]);
        for site in &row.sites {
            let via = site
                .rule_id
                .as_deref()
                .map(|rule| format!("rule {rule}"))
                .or_else(|| site.via_alias.clone())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                Cell::new(u.kind(&site.kind)),
                Cell::new(u.path(&site.location)),
                Cell::new(u.dim(site.in_function.as_deref().unwrap_or("<module>"))),
                Cell::new(u.dim(&via)),
                Cell::new(u.snippet(site.code.trim(), extension_for(&site.file))),
            ]);
        }
        cli_println!("{table}");
    }
    if row.finding_items.is_empty() {
        cli_println!();
        cli_println!(
            "    {} {}",
            u.kind("TAINT FLOWS:"),
            u.dim("no taint-analysis flow passes through this package")
        );
        return Ok(());
    }
    cli_println!();
    cli_println!(
        "    {} {} flow(s) through this package",
        u.kind("TAINT FLOWS:"),
        row.finding_items.len()
    );
    for (idx, item) in row.finding_items.iter().enumerate() {
        cli_println!();
        cli_println!("{}", u.ruler('─', 70));
        let flow = flow_from_finding_hops(&item.finding, idx);
        render_taint_analysis_text_unit(workspace, pack, item, idx, flow.as_ref(), 0, 1)?;
    }
    Ok(())
}

fn dep_block_cost_bytes(r: &DependencyPresentationRow) -> u64 {
    let chip_bytes = r.language.len()
        + r.key.len()
        + r.tags.iter().map(|s| s.len() + 2).sum::<usize>()
        + r.signals.iter().map(|s| s.len() + 2).sum::<usize>()
        + r.rules.len().to_string().len()
        + 96;
    let evidence_bytes = r.evidence_files.iter().map(|file| file.len() + 8).sum::<usize>();
    let description_bytes = r
        .rules
        .iter()
        .map(|rule| rule.rule_id.len() + rule.description.trim().len() + 96)
        // Bullet rendering wraps descriptions and adds indentation on
        // each line. Description bytes dominate the block; a fixed
        // per-description allowance keeps pages under context without
        // wasting most of the requested budget.
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
    tag: Option<String>,
    rule: Option<String>,
    state: Option<String>,
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
    if let Some(pattern) = rule.as_deref() {
        Regex::new(pattern).with_context(|| format!("invalid --rule regex `{pattern}`"))?;
    }
    let enabled_filter = match state.as_deref() {
        Some("enabled") => Some(true),
        Some("disabled") => Some(false),
        Some(other) => anyhow::bail!("unknown --state `{other}` (expected enabled|disabled)"),
        None => None,
    };

    let pack_facade = bonsai_sdk::SecurityPack::new(pack);
    let pack_options = PackInventoryOptions {
        lang: lang.clone(),
        category: category.clone(),
        kind: kind_filter,
        severity: sev_floor,
        tag: tag.clone(),
        rule: rule.clone(),
        enabled: enabled_filter,
        taint_replay_examples: taint_replay,
    };
    let base_filters_hash = filter_signature(&[
        ("kind", "pack"),
        ("lang", lang.as_deref().unwrap_or("")),
        ("category", category.as_deref().unwrap_or("")),
        ("tag", tag.as_deref().unwrap_or("")),
        ("rule", rule.as_deref().unwrap_or("")),
        ("state", state.as_deref().unwrap_or("")),
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
        (r.rule_id.len()
            + r.language.len()
            + r.source_path.len()
            + r.tag.as_deref().map_or(0, str::len)
            + r.description.len()
            + r.yaml.len()
            + 96) as u64
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
                    let result_incomplete_reasons = paged_json_incomplete_reasons("security/pack", info);
                    let payload = serde_json::json!({
                        "analysis_complete": true,
                        "analysis_incomplete_reasons": [],
                        "result_complete": result_incomplete_reasons.is_empty(),
                        "result_incomplete_reasons": result_incomplete_reasons,
                        "rows": paged,
                        "page": page_info_to_json(info),
                    });
                    crate::output::emit_json_document(&payload)?;
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
                    let enabled_count = display_rows.iter().filter(|row| row.enabled).count();
                    let languages = display_rows
                        .iter()
                        .map(|row| row.language.as_str())
                        .collect::<std::collections::BTreeSet<_>>();
                    cli_println!(
                        "{}",
                        u.dim(&format!(
                            "security pack — {row_count} rule(s) · {} enabled · {} disabled · {} language(s)",
                            enabled_count,
                            display_rows.len().saturating_sub(enabled_count),
                            languages.len()
                        ))
                    );
                    // The canonical rows are one flat sorted list (language,
                    // kind, family, id). Text prints each rule as the YAML it is
                    // written in, under its pack file, so a reader sees the rule
                    // exactly as the matcher loads it.
                    let mut current_file: Option<&str> = None;
                    for row in &display_rows {
                        if current_file != Some(row.source_path.as_str()) {
                            cli_println!();
                            cli_println!("{} {}", u.heading("──"), u.path(&row.source_path));
                            current_file = Some(row.source_path.as_str());
                        }
                        let state = if row.enabled {
                            u.name("enabled")
                        } else {
                            u.warn("disabled")
                        };
                        cli_println!();
                        let mut heading = vec![
                            format!(
                                "{} {}",
                                u.annotation(&format!("[{}]", row.kind)),
                                u.name(&row.rule_id)
                            ),
                            u.kind(&row.family),
                        ];
                        if let Some(severity) = row.severity.as_deref() {
                            heading.push(severity_cell(u, severity));
                        }
                        heading.push(state);
                        cli_println!("{}", heading.join(&u.dim(" · ")));
                        if row.yaml.is_empty() {
                            cli_println!("  {}", u.dim(&row.description));
                        } else {
                            for line in u.yaml_block(&row.yaml, &row.language) {
                                cli_println!("  {line}");
                            }
                        }
                    }
                    if display_rows.is_empty() {
                        cli_println!();
                        cli_println!("{}", u.dim("(no rules match the selected filters)"));
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
        let row_cost = |language: &bonsai_sdk::PackAuditLanguage| {
            serde_json::to_vec(language).map_or(512, |bytes| bytes.len() as u64 + 128)
        };
        page_cache::emit_paged_text(
            workspace,
            &report.languages,
            paging_cfg,
            "security/pack/audit",
            filters_hash,
            row_cost,
            |languages, info, _cfg| {
                let result_complete = info.page_number == 1 && info.is_last;
                let payload = serde_json::json!({
                    "analysis_complete": true,
                    "analysis_incomplete_reasons": [],
                    "result_complete": result_complete,
                    "result_incomplete_reasons": if result_complete {
                        Vec::<String>::new()
                    } else {
                        paged_json_incomplete_reasons("security/pack/audit", info)
                    },
                    "canonical_source_families": report.canonical_source_families,
                    "canonical_sink_families": report.canonical_sink_families,
                    "sink_family_short_labels": report.sink_family_short_labels,
                    "languages": languages,
                    "page": page_info_to_json(info),
                });
                crate::output::emit_json_document(&payload)?;
                Ok(())
            },
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

    let mut source_headers: Vec<&str> = vec!["lang"];
    source_headers.extend(report.canonical_source_families.iter().map(String::as_str));
    source_headers.push("gaps");
    let mut source_table = u.table(&source_headers);
    source_table.set_content_arrangement(comfy_table::ContentArrangement::Disabled);
    for language in &report.languages {
        let mut row = vec![Cell::new(u.name(&language.language))];
        let mut gaps = Vec::new();
        for family in &report.canonical_source_families {
            let entry = language.source_families.get(family);
            if entry.is_some_and(|count| count.not_applicable) {
                row.push(Cell::new(u.dim("n/a")));
                continue;
            }
            let enabled = entry.map_or(0, |count| count.enabled);
            row.push(Cell::new(count_cell(u, enabled, 3)));
            if enabled == 0 {
                gaps.push(family.as_str());
            }
        }
        row.push(Cell::new(u.warn(&if gaps.is_empty() {
            "-".to_string()
        } else {
            gaps.join(",")
        })));
        source_table.add_row(row);
    }
    cli_println!("\n{}", u.heading("source boundary coverage"));
    cli_println!("{source_table}");
    cli_println!(
        "{}",
        u.dim(
            "source families are rulepack YAML files; zeroes are explicit coverage gaps, not hidden totals."
        )
    );
    let descriptions = report
        .languages
        .iter()
        .flat_map(|language| {
            let sources = language
                .source_families
                .iter()
                .filter(|(_, count)| count.not_applicable)
                .map(|(family, _)| format!("{}/source:{family}", language.language));
            let sinks = language
                .sinks
                .iter()
                .filter(|(_, count)| count.not_applicable)
                .map(|(family, _)| format!("{}/sink:{family}", language.language));
            sources.chain(sinks)
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
        let row_cost = |language: &bonsai_sdk::PackTreeLanguage| {
            serde_json::to_vec(language).map_or(512, |bytes| bytes.len() as u64 + 128)
        };
        page_cache::emit_paged_text(
            workspace,
            &report.languages,
            paging_cfg,
            "security/pack/tree",
            filters_hash,
            row_cost,
            |languages, info, _cfg| {
                let result_complete = info.page_number == 1 && info.is_last;
                let payload = serde_json::json!({
                    "analysis_complete": true,
                    "analysis_incomplete_reasons": [],
                    "result_complete": result_complete,
                    "result_incomplete_reasons": if result_complete {
                        Vec::<String>::new()
                    } else {
                        paged_json_incomplete_reasons("security/pack/tree", info)
                    },
                    "languages": languages,
                    "page": page_info_to_json(info),
                });
                crate::output::emit_json_document(&payload)?;
                Ok(())
            },
        )?;
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
                    // Same facts as the JSON tree rule: id, severity (sinks
                    // only), enabled state, and tag.
                    let mut facts = Vec::new();
                    if let Some(severity) = r.severity {
                        facts.push(severity_cell(u, severity.as_str()));
                    }
                    facts.push(if r.enabled {
                        u.name("enabled")
                    } else {
                        u.warn("disabled")
                    });
                    if let Some(tag) = r.tag.as_deref() {
                        facts.push(u.dim(tag));
                    }
                    cli_println!("      {}  {}", u.name(&r.id), facts.join(&u.dim(" · ")));
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
