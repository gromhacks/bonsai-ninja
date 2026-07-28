//! SDK-level security analyses.
//!
//! This module owns the command-independent orchestration behind
//! `security taint-analysis` and `security source-analysis`. CLI code
//! should call these functions, then handle only formatting, paging,
//! progress UI, and themed rendering.

use crate::deps::{build_inventory, DependencyInventory};
use crate::finding::{
    compute_finding_id, AlternateTaintFlow, Finding, FindingMatch, FindingStatus, TaintPropagationArg,
    TaintPropagationStep, TaintedArgInfo,
};
use crate::loader::Rulepack;
use crate::matcher::{
    callback_extension_attribution_match, infer_entry_point_sources_for_files_with_progress,
    match_rules_against_facts_for_inventory_with_progress_on_files,
    match_rules_against_facts_for_sink_inventory_with_progress_on_files,
    match_rules_against_facts_for_taint_support_with_progress_on_files,
    match_rules_against_facts_for_taint_with_progress_on_files,
    match_rules_against_facts_with_progress_on_files, rule_match_passes_constraints_with_taint_view,
    rule_target_matches_call, InterTaintView, RuleMatch, RuntimeDisabledRule,
};
use crate::rule::{
    ConstraintKind, ContextFlowRole, FlowClass, GuardProfile, MatchKind, MatchOrigin,
    PathContainmentGuardSemantics, PostSinkPolicy, RelativePathContainmentGuardSemantics, Rule, RuleKind,
    RuleTarget, Severity, SourceCallbackArgSemantics,
};
use crate::sanitizer_credit::{sanitizer_credits_sink_tag, sanitizer_tag_is_recognized_non_crediting};
use ahash::{AHashMap, AHashSet};
use anyhow::Result;
use bonsai_common::{FileId, FuncId, Precision, Span, SymbolId};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{
    branch_condition_fact_for_span, AssignValueKind, BranchConditionFact, BranchConditionPolarity,
    ConditionEquality, ConditionExpressionFact, ConditionOperandFact, DeclKind, FlowEvent, LanguageRegistry,
};
use bonsai_taint::{
    compose_idg_seed_nodes, CallResultPassthrough, CleanOutputOverwrite, EntryTaintGraph, IdgSeedRequest,
    InterTaintCaches, InterTaintConfig, OutputArgFlow, ReceiverStatePropagation, SourceCallbackArgs,
    SourceOutputArgs, TaintedCall, TaintedCallEdge, TokenSet,
};
use bonsai_workspace::Workspace;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{mpsc, Arc, OnceLock};
use std::time::{Duration, Instant};

mod chain_executor;
mod clean_overwrite;
mod execution;
mod findings_build;
mod guard_sanitizers;
mod prototype_guard;
mod source_seeds;
mod taint_cache;
mod validation;
use clean_overwrite::{
    call_arg_target_keys, clean_conditional_helper_identifier, clean_overwrite_callee_tail,
    clean_overwrite_target_key, interprocedural_clean_overwrite_kills_lineage_arg, looks_like_clean_constant,
    numeric_literal, quoted_literal, same_function_clean_overwrite_kills_sink_arg,
    tainted_arg_info_from_events, tainted_arg_target_keys, CleanOverwritePolicy,
};
#[cfg(test)]
use clean_overwrite::{
    clean_conditional_value_part, clean_output_call_overwrites_target, try_region_clean_overwrites_target,
    value_part_contains_only_clean_literals,
};
use execution::{
    append_taint_target_key, append_taint_target_node_key, build_findings_chain_aware,
    effective_source_seed_key, identifier_tokens_outside_strings, sorted_seed_key_with_anchor,
    source_analysis_lineage_func_scope, source_analysis_worker_count, source_can_precede_sink,
    ChainAnalysisRequest, ScheduledSourceGroup, SourceGroupExecutor, SourceWorkItem,
};
use findings_build::{
    build_pattern_only_findings, make_finding, rule_has_taint_predicate, rule_is_non_taint_sink,
    rule_is_pattern_only_finding, FindingBuildContext,
};
#[cfg(test)]
use guard_sanitizers::header_char_allowlist_condition;
use guard_sanitizers::{
    character_escape_sanitizer, configured_argument_factory_guard_sanitizer,
    dev_only_environment_guard_sanitizer, finite_literal_map_lookup_allowlist_sanitizer,
    finite_literal_selection_sanitizer, go_jwt_inline_keyfunc_algorithm_guard_sanitizer,
    go_same_origin_redirect_helper_guard_sanitizer, go_xml_decoder_hardening_sanitizer,
    guarded_char_append_allowlist_sanitizer, java_local_html_escape_helper_return_sanitizer,
    js_ts_local_html_escape_helper_sanitizer, local_ldap_escape_helper_sanitizer,
    nosql_eq_filter_wrapper_sanitizer, parameterized_query_guard_sanitizer,
    path_consumer_containment_guard_sanitizer, path_containment_guard_sanitizer, place_is_assigned_between,
    python_compiled_regex_guard_sanitizer, python_url_ssrf_guard_sanitizer, receiver_factory_guard_sanitizer,
    relative_path_containment_guard_sanitizer, runtime_type_rejection_guard_sanitizer,
    source_sink_pair_is_low_signal, terminal_rejection_predicate_guard_span, url_network_guard_sanitizer,
};
use prototype_guard::prototype_pollution_sink_is_guarded;
#[cfg(test)]
use source_seeds::seed_descendant_aliases_for_qualified_source_reads;
use source_seeds::{
    collect_source_seed_targets, insert_descendant_taint_aliases, insert_taint_aliases,
    security_text_matches_source_strict,
};
pub use validation::validate_pack;
#[cfg(test)]
use validation::{
    lowercase_receiver_token_from_regex, package_signal_distro_smell, regex_prefix_is_receiver_agnostic,
};

type InventoryMatchIdentity = (String, String, u32, u32, String, Option<String>);
type SourceMatchDedupeKey = (String, String, u64, u64, String);
type SourceMatchDedupeValue<'a> = (usize, &'a RuleMatch, FuncId, u64);

/// Public security analysis has one accuracy contract: findings must
/// be backed by proven static evidence. Diagnostic-only precision
/// classes can be retained internally for observability, but they do
/// not become user-facing findings.
pub(crate) const PUBLIC_SEMANTIC_MAX_PRECISION: Precision = Precision::Narrowed;

/// Phase-aware progress event emitted by `run_taint_analysis_with_phase_progress`
/// and `run_source_analysis_with_phase_progress`. Long-running phases
/// announce themselves with a known total, then tick once per item;
/// callers can render a progress bar per phase without having to
/// hard-code phase totals on the UI side.
#[derive(Clone, Debug)]
pub enum AnalysisProgress {
    /// A new phase has begun. `total` is the number of `PhaseTicked`
    /// events the engine will emit before `PhaseFinished`. `0` means
    /// the total is unknown — render a spinner.
    PhaseStarted {
        /// Stable, human-readable phase label (used as the bar caption).
        label: &'static str,
        /// Expected number of ticks before this phase finishes.
        total: u64,
    },
    /// One unit of work has been completed within the current phase.
    PhaseTicked,
    /// The current phase has finished. Pairs with the most recent
    /// `PhaseStarted`.
    PhaseFinished,
    /// Structured observability note for cache/scope decisions that
    /// are not naturally represented as a progress bar.
    Note {
        /// Stable note category, e.g. `scope`, `taint-cache`.
        label: &'static str,
        /// Human-readable detail. CLI renders this on stderr; SDK
        /// callers can collect it for logs or UI surfaces.
        detail: String,
    },
}

#[derive(Clone, Debug)]
pub struct TaintAnalysisOptions {
    pub source: Option<String>,
    /// Optional security representative flow id (`F:<hex>`) filter.
    /// Security flow ids include taint-path identity; they are not the
    /// same namespace as inspect's structural chain-only `F:` ids, but
    /// they still use the shared stable-id prefix for report navigation.
    pub flow_id: Option<String>,
    pub trust: Option<String>,
    pub category: Option<String>,
    pub sink: Option<String>,
    pub severity: Option<Severity>,
    pub tag: Option<String>,
    pub files: Vec<String>,
    pub exclude_files: Vec<String>,
    /// Opt-in: when true, augment loaded source rules with synthetic
    /// per-function entry-point sources (every parameter of every
    /// unreferenced or framework-decorated function becomes its own
    /// `entry-point.unreferenced_entry.param_N` / `entry-point.class_field.inherited`
    /// source). Disabled by default — produces O(functions) noisy
    /// inferred-trust findings that drown out real source-rule matches.
    pub include_inferred_sources: bool,
    /// Opt-in: include exact local pattern findings in taint-analysis
    /// output. Disabled by default because pattern-only rows do not
    /// prove source-to-sink reachability and should not appear in a
    /// source-to-sink taint report unless a caller explicitly requests
    /// mixed local-pattern inventory.
    pub include_pattern_only: bool,
    /// Opt-in diagnostic switch. Sanitizer rules are evidence attached to
    /// propagated paths; public reports suppress paths whose relevant sink
    /// class has been sanitizer-cleared unless this is set.
    pub show_sanitized: bool,
    /// Optional maximum tolerated flow precision. Public security
    /// analysis is semantic-only: `Some(Precision::Narrowed)` keeps
    /// exact and narrowed findings and rejects broad diagnostic
    /// classes.
    pub max_precision: Option<Precision>,
    /// When true, drop findings whose source OR sink lives in a
    /// conventional test path (`test/`, `tests/`, `*_test.go`, etc.).
    /// See `crate::finding::path_is_test_file` for the exact rule.
    pub exclude_tests: bool,
    /// Attach full per-hop source bodies to every surviving finding.
    /// SARIF/full exports need this. Broad paged CLI views leave it off
    /// and render lightweight findings so large repositories do not
    /// duplicate source bodies for every finding before pagination.
    pub attach_flow_evidence: bool,
    /// Override the workspace taint-graph resident cache for this
    /// analysis. `None` preserves the workspace/SDK default. One-shot
    /// broad CLI scans set this to `Some(0)` so every source group is
    /// still analyzed, but decoded graphs are not retained across
    /// groups and cannot accumulate into multi-GB resident state.
    pub taint_graph_resident_cache_entries: Option<usize>,
}

impl Default for TaintAnalysisOptions {
    fn default() -> Self {
        Self {
            source: None,
            flow_id: None,
            trust: None,
            category: None,
            sink: None,
            severity: None,
            tag: None,
            files: Vec::new(),
            exclude_files: Vec::new(),
            include_inferred_sources: false,
            include_pattern_only: false,
            show_sanitized: false,
            max_precision: Some(PUBLIC_SEMANTIC_MAX_PRECISION),
            exclude_tests: false,
            attach_flow_evidence: true,
            taint_graph_resident_cache_entries: None,
        }
    }
}

impl TaintAnalysisOptions {
    /// Enforce the production semantic-only precision contract.
    ///
    /// `Exact` remains exact. Every other request is capped at
    /// `Narrowed`, so broad diagnostic classes cannot leak into
    /// user-facing taint results through SDK defaults or custom callers.
    #[must_use]
    pub fn semantic_precision_only(mut self) -> Self {
        self.max_precision = Some(match self.max_precision {
            Some(Precision::Exact) => Precision::Exact,
            _ => PUBLIC_SEMANTIC_MAX_PRECISION,
        });
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct SourceAnalysisOptions {
    pub source: Option<String>,
    pub trust: Option<String>,
    pub category: Option<String>,
    pub tag: Option<String>,
    pub files: Vec<String>,
    pub exclude_files: Vec<String>,
    /// Drop direct source matches and rendered lineage paths that cross
    /// conventional test files. Mirrors `TaintAnalysisOptions::exclude_tests`.
    pub exclude_tests: bool,
    /// See `TaintAnalysisOptions::include_inferred_sources`.
    pub include_inferred_sources: bool,
    /// Lineage evidence bounds for rendered source-flow paths. Default
    /// command output keeps this representative and explicitly marks
    /// omissions; callers that request an uncapped audit scope should
    /// pass [`SourceLineageLimits::unbounded`].
    pub lineage_limits: SourceLineageLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceLineageLimits {
    pub max_hops: usize,
    pub max_paths: usize,
}

impl SourceLineageLimits {
    #[must_use]
    pub const fn bounded_default() -> Self {
        Self {
            max_hops: SOURCE_ANALYSIS_LINEAGE_RENDER_HOPS,
            max_paths: SOURCE_ANALYSIS_LINEAGE_RENDER_PATHS,
        }
    }

    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            max_hops: usize::MAX,
            max_paths: usize::MAX,
        }
    }
}

impl Default for SourceLineageLimits {
    fn default() -> Self {
        Self::bounded_default()
    }
}

#[derive(Clone, Debug, Default)]
pub struct SecurityInventoryOptions {
    pub rule: Option<String>,
    pub rule_regex: Option<String>,
    pub trust: Option<String>,
    pub category: Option<String>,
    pub severity: Option<Severity>,
    pub tag: Option<String>,
    pub files: Vec<String>,
    pub exclude_files: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct DependencyInventoryOptions {
    pub framework: Option<String>,
    pub severity: Option<Severity>,
    pub files: Vec<String>,
    pub exclude_files: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PackInventoryOptions {
    pub lang: Option<String>,
    pub category: Option<String>,
    pub kind: Option<RuleKind>,
    pub severity: Option<Severity>,
    /// When set, `validate_pack` replays each taint-dependent rule's
    /// positive `match_examples` through live taint analysis (seeding the
    /// example's inferred inputs as sources) and asserts the rule fires,
    /// instead of skipping it as "not statically checkable". Off by default
    /// because it runs taint per example — opt in for the deep CI gate via
    /// `pack --validate --taint-replay`.
    pub taint_replay_examples: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecurityMatchRow {
    pub rule_id: String,
    pub tag: Option<String>,
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub owasp: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub frameworks: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<String>,
    pub language: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub text: String,
    pub enclosing_fn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackRuleRow {
    pub rule_id: String,
    pub language: String,
    pub kind: String,
    pub family: String,
    pub tag: Option<String>,
    pub severity: Option<String>,
    pub enabled: bool,
    pub packages: Vec<String>,
    pub frameworks: Vec<String>,
    pub description: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackAuditReport {
    pub languages: Vec<PackAuditLanguage>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackAuditLanguage {
    pub language: String,
    pub security_model: String,
    pub canonical_sink_families_applicable: bool,
    pub sinks: BTreeMap<String, PackAuditFamilyCount>,
    pub sources: PackAuditCount,
    pub sanitizers: PackAuditCount,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackAuditFamilyCount {
    pub enabled: u32,
    pub disabled: u32,
    pub not_applicable: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PackAuditCount {
    pub enabled: u32,
    pub disabled: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackTreeReport {
    pub languages: Vec<PackTreeLanguage>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackTreeLanguage {
    pub language: String,
    pub kinds: BTreeMap<String, Vec<PackTreeFile>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackTreeFile {
    pub file: String,
    pub rules: Vec<PackTreeRule>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackTreeRule {
    pub id: String,
    pub severity: Option<String>,
    pub enabled: bool,
    pub tag: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackValidationReport {
    pub valid: bool,
    pub rule_count: usize,
    pub enabled_rule_count: usize,
    pub disabled_rule_count: usize,
    pub disabled_waiting_reenable_count: usize,
    pub disabled_reason_counts: BTreeMap<String, usize>,
    /// Total `match_examples` entries across every rule (enabled +
    /// disabled). The header line splits this further so reviewers
    /// can see the enabled-only count vs. the grand total.
    pub example_count: usize,
    /// `match_examples` entries on enabled rules only. Equal to
    /// `enabled_rule_count` when each rule has exactly one example;
    /// strictly larger when some enabled rules carry multiple examples.
    pub enabled_example_count: usize,
    pub errors: usize,
    pub warnings: usize,
    pub issues: Vec<PackValidationIssue>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackValidationIssue {
    pub level: &'static str,
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub message: String,
}

pub const CANONICAL_SINK_FAMILIES: &[&str] = &[
    "cmdi",
    "sqli",
    "nosql",
    "path",
    "ssrf",
    "xss",
    "eval",
    "deserialization",
    "xxe",
    "ldap",
    "jwt",
    "crypto",
    "tls",
    "template",
    "open_redirect",
    "file_upload",
    "header_injection",
];

/// Languages whose sink taxonomy is intentionally ecosystem-specific,
/// so the canonical app/web-family audit matrix should render as not
/// applicable rather than as a wall of false coverage gaps.
pub const ECOSYSTEM_SPECIFIC_SINK_AUDIT_LANGS: &[&str] = &["solidity"];

pub fn security_model_for_lang(lang: &str) -> &'static str {
    if ECOSYSTEM_SPECIFIC_SINK_AUDIT_LANGS.contains(&lang) {
        "smart-contract"
    } else {
        "app-web-taint"
    }
}

/// Specific `(language, family)` cells where the empty state is a
/// deliberate design choice, not missing coverage.
pub const FAMILY_NOT_APPLICABLE: &[(&str, &str)] = &[("c", "deserialization")];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingWithChain {
    #[serde(flatten)]
    pub finding: Finding,
    #[serde(skip)]
    pub chain_funcs: Vec<FuncId>,
}

/// A rendered finding may contain multiple source/sink sites when they
/// collapse onto the same resolved semantic flow.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CombinedFindingWithChain {
    #[serde(flatten)]
    pub finding: Finding,
    #[serde(skip)]
    pub chain_funcs: Vec<FuncId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_sources: Vec<FindingMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_sinks: Vec<FindingMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_finding_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaintAnalysisReport {
    pub findings: Vec<CombinedFindingWithChain>,
    pub source_rule_count: usize,
    pub sink_rule_count: usize,
    pub sanitizer_rule_count: usize,
    /// True only when the scan itself and every emitted finding have complete
    /// semantic evidence. This is independent of CLI pagination: a one-page
    /// response must not look complete when parsing or workspace resolution
    /// left analysis gaps.
    #[serde(default)]
    pub analysis_complete: bool,
    /// Stable, machine-readable scan-level reasons for incompleteness.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub analysis_incomplete_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_disabled_rules: Vec<RuntimeDisabledRule>,
}

impl TaintAnalysisReport {
    /// Tally findings by severity tier — returns
    /// `(critical, high, medium)` counts for the CLI's summary line.
    #[must_use]
    pub fn severity_counts(&self) -> (usize, usize, usize) {
        let critical = self
            .findings
            .iter()
            .filter(|combined| combined.finding.severity == Some(Severity::Critical))
            .count();
        let high = self
            .findings
            .iter()
            .filter(|combined| combined.finding.severity == Some(Severity::High))
            .count();
        let medium = self
            .findings
            .iter()
            .filter(|combined| combined.finding.severity == Some(Severity::Medium))
            .count();
        (critical, high, medium)
    }
}

#[derive(Clone, Debug, Default)]
struct ResolutionCoverage {
    unresolved_workspace_sites: AHashSet<(FuncId, Span)>,
}

impl ResolutionCoverage {
    fn from_graph(
        graph: &bonsai_callgraph::ResolvedCallGraph,
        analyzed_funcs: impl IntoIterator<Item = FuncId>,
    ) -> Self {
        let analyzed_funcs: AHashSet<FuncId> = analyzed_funcs.into_iter().collect();
        Self {
            unresolved_workspace_sites: graph
                .unresolved_workspace_call_sites()
                .filter(|(caller, _)| analyzed_funcs.contains(caller))
                .collect(),
        }
    }
}

fn workspace_analysis_incomplete_reasons(
    ws: &Workspace,
    scan_files: &[FileId],
    resolution: Option<&ResolutionCoverage>,
) -> Vec<String> {
    let mut reasons: BTreeSet<String> = ws
        .parser_incomplete_reasons_for_files(scan_files)
        .into_iter()
        .collect();

    if let Some(resolution) = resolution {
        let unresolved_workspace_calls = resolution.unresolved_workspace_sites.len();
        if unresolved_workspace_calls > 0 {
            reasons.insert(format!(
                "unresolved-workspace-call-sites:{unresolved_workspace_calls}"
            ));
        }
    }

    reasons.into_iter().collect()
}

fn taint_analysis_incomplete_reasons(
    ws: &Workspace,
    scan_files: &[FileId],
    findings: &[CombinedFindingWithChain],
    resolution: Option<&ResolutionCoverage>,
) -> Vec<String> {
    let mut reasons: BTreeSet<String> = workspace_analysis_incomplete_reasons(ws, scan_files, resolution)
        .into_iter()
        .collect();
    let incomplete_findings = findings
        .iter()
        .filter(|combined| !combined.finding.analysis_complete)
        .count();
    if incomplete_findings > 0 {
        reasons.insert(format!("incomplete-finding-evidence:{incomplete_findings}"));
        for reason in findings
            .iter()
            .flat_map(|combined| combined.finding.analysis_incomplete_reasons.iter())
        {
            reasons.insert(format!("finding-evidence:{reason}"));
        }
    }
    reasons.into_iter().collect()
}

#[derive(Clone, Debug)]
pub struct SourceAnalysisCandidate {
    pub source: FindingMatch,
    pub path: Vec<FuncId>,
    pub flow_id: String,
    pub chain_names: Vec<String>,
    pub taint_path: Vec<TaintPropagationStep>,
    pub precision: Precision,
    pub lineage: SourceLineageStatus,
}

#[derive(Clone, Debug, Serialize)]
pub struct CombinedSourceAnalysisCandidate {
    pub source: FindingMatch,
    pub chain_names: Vec<String>,
    pub path: Vec<FuncId>,
    pub flow_id: String,
    pub taint_path: Vec<TaintPropagationStep>,
    pub precision: Precision,
    pub lineage: SourceLineageStatus,
    pub additional_sources: Vec<FindingMatch>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SourceLineageStatus {
    pub complete: bool,
    pub truncated_hops: bool,
    pub omitted_paths: usize,
    pub emitted_paths: usize,
    pub max_hops: usize,
    pub max_paths: usize,
}

impl SourceLineageStatus {
    fn complete() -> Self {
        Self {
            complete: true,
            truncated_hops: false,
            omitted_paths: 0,
            emitted_paths: 0,
            max_hops: SOURCE_ANALYSIS_LINEAGE_RENDER_HOPS,
            max_paths: SOURCE_ANALYSIS_LINEAGE_RENDER_PATHS,
        }
    }

    fn from_lineage(
        emission: &SourceLineageEmission<'_>,
        stats: SourceLineageEnumeration,
        emitted_index: usize,
    ) -> Self {
        // Omitted paths are enumeration-level evidence, not a property
        // of every emitted representative path. Attach them once so
        // top-level summaries report the real omission count instead
        // of multiplying it by the number of rows.
        let omitted_paths = if emitted_index == 0 {
            stats.omitted_paths
        } else {
            0
        };
        let incomplete = emission.truncated_hops || omitted_paths > 0;
        Self {
            complete: !incomplete,
            truncated_hops: emission.truncated_hops,
            omitted_paths,
            emitted_paths: 1,
            max_hops: stats.max_hops,
            max_paths: stats.max_paths,
        }
    }

    pub fn is_complete_default(&self) -> bool {
        self.complete && !self.truncated_hops && self.omitted_paths == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SourceLineageSummary {
    pub complete: bool,
    pub incomplete_flows: usize,
    pub truncated_hop_flows: usize,
    pub omitted_paths: usize,
    pub emitted_paths: usize,
    pub max_hops: usize,
    pub max_paths: usize,
}

impl Default for SourceLineageSummary {
    fn default() -> Self {
        Self {
            complete: true,
            incomplete_flows: 0,
            truncated_hop_flows: 0,
            omitted_paths: 0,
            emitted_paths: 0,
            max_hops: SOURCE_ANALYSIS_LINEAGE_RENDER_HOPS,
            max_paths: SOURCE_ANALYSIS_LINEAGE_RENDER_PATHS,
        }
    }
}

impl SourceLineageSummary {
    pub fn from_candidates(candidates: &[CombinedSourceAnalysisCandidate]) -> Self {
        Self::from_statuses(candidates.iter().map(|candidate| candidate.lineage))
    }

    pub fn is_complete(&self) -> bool {
        self.complete
            && self.incomplete_flows == 0
            && self.truncated_hop_flows == 0
            && self.omitted_paths == 0
    }

    fn from_statuses<I>(statuses: I) -> Self
    where
        I: IntoIterator<Item = SourceLineageStatus>,
    {
        let mut summary = Self::default();
        for status in statuses {
            if !status.is_complete_default() {
                summary.incomplete_flows = summary.incomplete_flows.saturating_add(1);
            }
            if status.truncated_hops {
                summary.truncated_hop_flows = summary.truncated_hop_flows.saturating_add(1);
            }
            summary.omitted_paths = summary.omitted_paths.saturating_add(status.omitted_paths);
            summary.emitted_paths = summary.emitted_paths.saturating_add(status.emitted_paths);
            summary.max_hops = summary.max_hops.max(status.max_hops);
            summary.max_paths = summary.max_paths.max(status.max_paths);
        }
        summary.complete = summary.incomplete_flows == 0;
        summary
    }
}

#[derive(Clone, Debug)]
pub struct SourceAnalysisReport {
    pub candidates: Vec<CombinedSourceAnalysisCandidate>,
    pub source_rule_count: usize,
    pub lineage_summary: SourceLineageSummary,
    /// True only when both the selected syntax scope and the emitted source
    /// lineage evidence were analyzed completely.
    pub analysis_complete: bool,
    /// Stable, machine-readable scan and lineage coverage gaps.
    pub analysis_incomplete_reasons: Vec<String>,
    pub runtime_disabled_rules: Vec<RuntimeDisabledRule>,
}

// Rendering guard for the current source-flow report shape. Naively
// enumerating every raw trace path can explode even in `examples/`;
// the production-grade exactness follow-up is to report canonical
// reachability summaries or stream an explicit incomplete marker,
// not to silently materialize an unbounded path product in memory.
const SOURCE_ANALYSIS_LINEAGE_RENDER_HOPS: usize = 6;
const SOURCE_ANALYSIS_LINEAGE_RENDER_PATHS: usize = 24;

struct SelectedTaintRules<'a> {
    sources: Vec<&'a Rule>,
    sinks: Vec<&'a Rule>,
    sanitizers: Vec<&'a Rule>,
    sink_rule_count: usize,
    factory_returns: Arc<crate::matcher::FactoryReturns>,
}

fn select_taint_analysis_rules<'a>(
    ws: &Workspace,
    pack: &'a Rulepack,
    options: &TaintAnalysisOptions,
) -> Result<SelectedTaintRules<'a>> {
    let mut sources = select_rules(pack, RuleKind::Source, None, options.source.as_deref(), |rule| {
        source_rule_matches_filters(rule, options.trust.as_deref(), options.category.as_deref(), None)
    })?;
    let mut sinks = select_rules(pack, RuleKind::Sink, None, options.sink.as_deref(), |rule| {
        options
            .severity
            .is_none_or(|minimum| rule.severity.is_some_and(|severity| severity >= minimum))
            && options
                .tag
                .as_deref()
                .is_none_or(|tag| rule.tag.as_deref() == Some(tag))
    })?;
    let mut sanitizers = select_rules(pack, RuleKind::Sanitizer, None, None, |_| true)?;

    // `returns_type` rules are typing declarations for factory results. They
    // enrich AST-derived receiver facts but never produce findings themselves.
    sources.retain(|rule| rule.returns_type.is_none());
    sinks.retain(|rule| rule.returns_type.is_none());
    sanitizers.retain(|rule| rule.returns_type.is_none());
    filter_rules_to_workspace_languages(ws, &mut sources);
    filter_rules_to_workspace_languages(ws, &mut sinks);
    filter_rules_to_workspace_languages(ws, &mut sanitizers);

    Ok(SelectedTaintRules {
        sink_rule_count: sinks.len(),
        factory_returns: crate::matcher::build_factory_returns(&pack.all_rules()),
        sources,
        sinks,
        sanitizers,
    })
}

struct TaintFindingFinalization<'a> {
    ws: &'a Workspace,
    sink_hits: &'a [RuleMatch],
    pattern_sink_hits: &'a [RuleMatch],
    pack: &'a Rulepack,
    options: &'a TaintAnalysisOptions,
}

fn finalize_taint_findings<F>(
    mut findings_raw: Vec<FindingWithChain>,
    request: TaintFindingFinalization<'_>,
    on_progress: &mut F,
) -> Vec<CombinedFindingWithChain>
where
    F: FnMut(AnalysisProgress),
{
    let TaintFindingFinalization {
        ws,
        sink_hits,
        pattern_sink_hits,
        pack,
        options,
    } = request;
    extend_implicit_context_findings(&mut findings_raw, sink_hits, pack, ws);
    on_progress(AnalysisProgress::PhaseStarted {
        label: "finalizing findings",
        total: 0,
    });
    let taint_sink_sites: AHashSet<(String, String, u32, u32)> = findings_raw
        .iter()
        .map(|finding| {
            (
                finding.finding.sink.rule_id.clone(),
                finding.finding.sink.file.clone(),
                finding.finding.sink.line,
                finding.finding.sink.column,
            )
        })
        .collect();
    findings_raw.extend(build_pattern_only_findings(
        ws,
        pattern_sink_hits,
        pack,
        &taint_sink_sites,
    ));
    // Sort findings_raw deterministically before grouping. Without
    // this, AHashSet-driven iteration upstream can flip which
    // finding becomes a group's primary vs additional source between
    // back-to-back runs of the same workspace, producing different
    // `S:` ids each time and breaking the json/sarif coherence
    // guard. The sort key combines source rule + sink rule + sink
    // location + finding_id so identical (source-rule, sink-site)
    // pairs always pick the same primary.
    findings_raw.sort_by(|a, b| {
        let af = &a.finding;
        let bf = &b.finding;
        af.source
            .rule_id
            .cmp(&bf.source.rule_id)
            .then_with(|| af.sink.rule_id.cmp(&bf.sink.rule_id))
            .then_with(|| af.sink.file.cmp(&bf.sink.file))
            .then_with(|| af.sink.line.cmp(&bf.sink.line))
            .then_with(|| af.sink.column.cmp(&bf.sink.column))
            .then_with(|| af.finding_id.cmp(&bf.finding_id))
    });
    // Select a concrete route before sink-level grouping. This preserves the
    // longstanding `--flow F:...` contract: asking for an alternate route
    // renders that route as the primary result instead of returning the
    // sink's otherwise preferred representative path.
    if let Some(flow_id) = options.flow_id.as_deref() {
        findings_raw.retain(|item| item.finding.representative_flow_id.as_deref() == Some(flow_id));
    }
    if let Some(max_precision) = options.max_precision {
        findings_raw.retain(|item| finding_precision_within(&item.finding.precision, max_precision));
    }
    if !options.exclude_files.is_empty() || options.exclude_tests {
        findings_raw.retain(|item| {
            !finding_has_excluded_path(ws, &item.finding, &options.exclude_files, options.exclude_tests)
        });
    }
    if !options.show_sanitized {
        findings_raw.retain(|item| item.finding.status != FindingStatus::Sanitized);
    }
    // Semantic dominance is route-specific. Run it before presentation
    // combines separate routes at one sink; otherwise a dominated primary
    // could discard valid alternates, or an inferred sibling route could
    // survive inside a concrete finding.
    let mut route_findings = findings_raw
        .into_iter()
        .map(combined_from_raw_finding)
        .collect::<Vec<_>>();
    drop_rulepack_terminal_dominated_findings(&mut route_findings, pack);
    drop_dominated_wrapper_findings(&mut route_findings);
    drop_dominated_receiver_projection_findings(&mut route_findings);
    // §C cleanup pass: when `--inferred-sources` synthesizes
    // `entry-point.class_field.inherited` sources for every record/
    // case-class component, each component reaches the sink through
    // the same flat container — so a sink that semantically consumes
    // only the `cmd` component still picks up inferred findings on
    // sibling components (`this.kind`, `this.user`). Drop those
    // sibling-attributed findings when (a) a concrete source already
    // covers the same chain end-to-end, and (b) the inferred source's
    // field name doesn't appear in any of the sink's `tainted_args`.
    route_findings = drop_field_mismatched_inferred_findings(route_findings);
    let mut findings = combine_route_findings_by_sink(route_findings, pack);
    // Sort highest-severity-first, then by finding id so two runs
    // produce identical output ordering.
    findings.sort_by(|a, b| {
        b.finding
            .severity
            .cmp(&a.finding.severity)
            .then_with(|| a.finding.sink.rule_id.cmp(&b.finding.sink.rule_id))
            .then_with(|| a.finding.sink.file.cmp(&b.finding.sink.file))
            .then_with(|| a.finding.sink.line.cmp(&b.finding.sink.line))
            .then_with(|| a.finding.sink.column.cmp(&b.finding.sink.column))
            .then_with(|| {
                source_reporting_rank(pack, &a.finding.source)
                    .cmp(&source_reporting_rank(pack, &b.finding.source))
            })
            .then_with(|| a.finding.finding_id.cmp(&b.finding.finding_id))
    });
    on_progress(AnalysisProgress::PhaseFinished);
    findings
}

fn hydrate_taint_flow_evidence<F>(
    ws: &Workspace,
    findings: &mut [CombinedFindingWithChain],
    attach: bool,
    on_progress: &mut F,
) where
    F: FnMut(AnalysisProgress),
{
    if attach {
        // Embed per-hop source bodies so JSON/SARIF carry the same code the text
        // view renders. Done last, on surviving findings only, so filtered-out
        // findings never pay the VFS read.
        on_progress(AnalysisProgress::PhaseStarted {
            label: "attaching flow evidence",
            total: findings.len() as u64,
        });
        let mut flow_body_cache = crate::flow_evidence::FlowBodyCache::new(ws);
        for combined in findings.iter_mut() {
            combined.finding.hops = flow_body_cache.build_flow_bodies(
                &combined.chain_funcs,
                &combined.finding.source,
                &combined.finding.taint_path,
                crate::flow_evidence::FlowRole::Sink,
            );
            on_progress(AnalysisProgress::PhaseTicked);
        }
        on_progress(AnalysisProgress::PhaseFinished);
    } else {
        on_progress(AnalysisProgress::PhaseStarted {
            label: "skipping bulk flow evidence",
            total: 0,
        });
        on_progress(AnalysisProgress::PhaseFinished);
    }
}

struct TaintReportCompletion<'a> {
    ws: &'a Workspace,
    scan_files: &'a [FileId],
    resolution: Option<&'a ResolutionCoverage>,
    unattributed_source_matches: usize,
    unattributed_sink_matches: usize,
    source_rule_count: usize,
    sink_rule_count: usize,
    sanitizer_rule_count: usize,
}

fn finish_taint_analysis_report(
    findings: Vec<CombinedFindingWithChain>,
    completion: TaintReportCompletion<'_>,
) -> TaintAnalysisReport {
    let TaintReportCompletion {
        ws,
        scan_files,
        resolution,
        unattributed_source_matches,
        unattributed_sink_matches,
        source_rule_count,
        sink_rule_count,
        sanitizer_rule_count,
    } = completion;
    let runtime_disabled_rules = crate::matcher::drain_runtime_disabled_rules();
    let mut analysis_incomplete_reasons: BTreeSet<String> =
        taint_analysis_incomplete_reasons(ws, scan_files, &findings, resolution)
            .into_iter()
            .collect();
    if unattributed_source_matches > 0 {
        analysis_incomplete_reasons.insert(format!(
            "unattributed-source-matches:{unattributed_source_matches}"
        ));
    }
    if unattributed_sink_matches > 0 {
        analysis_incomplete_reasons.insert(format!("unattributed-sink-matches:{unattributed_sink_matches}"));
    }
    if !runtime_disabled_rules.is_empty() {
        analysis_incomplete_reasons
            .insert(format!("runtime-disabled-rules:{}", runtime_disabled_rules.len()));
    }
    let analysis_incomplete_reasons: Vec<String> = analysis_incomplete_reasons.into_iter().collect();
    TaintAnalysisReport {
        findings,
        source_rule_count,
        sink_rule_count,
        sanitizer_rule_count,
        analysis_complete: analysis_incomplete_reasons.is_empty(),
        analysis_incomplete_reasons,
        runtime_disabled_rules,
    }
}

fn finish_taint_cache_write_through<F>(ws: &Workspace, persist_started: bool, on_progress: &mut F)
where
    F: FnMut(AnalysisProgress),
{
    if !persist_started {
        return;
    }
    let detail = taint_cache::finish_workspace_cache(ws).map_or_else(
        || "finish write-through failed".to_string(),
        |written| format!("finish write-through entries={written}"),
    );
    on_progress(AnalysisProgress::Note {
        label: "taint-cache",
        detail,
    });
}

/// Top-level taint analysis entry point. Combines source / sink /
/// sanitizer matching with interprocedural taint propagation and
/// returns the assembled findings. No progress reporting — see the
/// `_with_progress` and `_with_phase_progress` variants for live UI.
pub fn run_taint_analysis(
    ws: &Workspace,
    pack: &Rulepack,
    options: TaintAnalysisOptions,
) -> Result<TaintAnalysisReport> {
    run_taint_analysis_with_phase_progress(ws, pack, options, |_| {})
}

/// Backwards-compatible per-file progress callback. Each `&'static str`
/// label fires once per file processed within the labelled matching
/// phase. Newer callers should use [`run_taint_analysis_with_phase_progress`]
/// to receive begin/tick/end phase boundaries with totals (which lets
/// progress bars render a deterministic length and lets the post-
/// matching propagation phase show progress too).
pub fn run_taint_analysis_with_progress<F>(
    ws: &Workspace,
    pack: &Rulepack,
    options: TaintAnalysisOptions,
    mut on_match_file_done: F,
) -> Result<TaintAnalysisReport>
where
    F: FnMut(&'static str),
{
    let mut current_label: Option<&'static str> = None;
    run_taint_analysis_with_phase_progress(ws, pack, options, |event| match event {
        AnalysisProgress::PhaseStarted { label, .. } => current_label = Some(label),
        AnalysisProgress::PhaseTicked => {
            if let Some(label) = current_label {
                on_match_file_done(label);
            }
        }
        AnalysisProgress::PhaseFinished => current_label = None,
        AnalysisProgress::Note { .. } => {}
    })
}

/// Phase-aware variant of [`run_taint_analysis_with_progress`]. The
/// callback receives `PhaseStarted { label, total }` at the start of
/// each long-running phase, `PhaseTicked` per processed item, and
/// `PhaseFinished` when the phase completes — covering matching AND
/// the post-matching chain-build phase that the legacy callback can't
/// describe.
pub fn run_taint_analysis_with_phase_progress<F>(
    ws: &Workspace,
    pack: &Rulepack,
    options: TaintAnalysisOptions,
    mut on_progress: F,
) -> Result<TaintAnalysisReport>
where
    F: FnMut(AnalysisProgress),
{
    let _taint_analysis_guard = ws.lock_taint_analysis();
    let _dependency_package_snapshot = ws.db().workspace_root().map(|root| {
        crate::deps::begin_workspace_dependency_package_snapshot(&root, ws.db().vfs().instance_id())
    });
    let _ = crate::matcher::drain_runtime_disabled_rules();
    // The SDK may have opened the complete canonical graph while refreshing
    // warm sidecars. Endpoint discovery is a separate Tree-sitter compiler
    // phase and needs only the compact linkage headers. Preserve those
    // headers, then unmap graph/body readers before broad matching so the
    // parser scheduler measures the real phase-local working set. Every cache
    // miss reloads the same validated artifact; this changes locality and
    // wall time, never the analyzed files or fixed-point semantics.
    ws.release_idg_service_cache();
    ws.release_resolved_call_graph_cache();
    ws.release_exact_body_cache();
    ws.db().release_global_index();
    let options = options.semantic_precision_only();
    let SelectedTaintRules {
        sources,
        mut sinks,
        mut sanitizers,
        sink_rule_count: selected_sink_rule_count,
        factory_returns,
    } = select_taint_analysis_rules(ws, pack, &options)?;

    let scan_files = security_scan_files(ws, &options.files, &options.exclude_files, options.exclude_tests);
    let total_files = scan_files.len() as u64;
    on_progress(AnalysisProgress::Note {
        label: "scope",
        detail: format!(
            "taint-analysis files={} source_rules={} sink_rules={} sanitizer_rules={} include_inferred_sources={} exclude_tests={} file_filters={} exclude_filters={}",
            scan_files.len(),
            sources.len(),
            sinks.len(),
            sanitizers.len(),
            options.include_inferred_sources,
            options.exclude_tests,
            options.files.len(),
            options.exclude_files.len()
        ),
    });
    let mut source_hits = gather_taint_support_matches_phased(
        ws,
        &sources,
        "matching source rules",
        &scan_files,
        total_files,
        &factory_returns,
        &mut on_progress,
    );
    // Inferred per-function entry-point sources are opt-in (was: emitted
    // by default whenever no `--source` regex was given). Default off
    // because these synthetic sources O(functions) and outrank real
    // source-rule findings in unfiltered output. Pass
    // `--inferred-sources` to restore the legacy behavior; combine with
    // `--trust local --category inferred` to view only the inferred set.
    if options.include_inferred_sources && options.source.is_none() {
        // A broad inferred entry-point param source is redundant noise
        // when a concrete source in the same function is rooted at that
        // same parameter (e.g. Go's `unreferenced_entry.param_1` for `r`
        // duplicates the concrete `r.URL.Query().Get(...)` source). Drop
        // the inferred param so the precise source is the sole evidence.
        let concrete_param_bases = concrete_source_param_bases(pack, &source_hits);
        on_progress(AnalysisProgress::PhaseStarted {
            label: "inferring entry-point sources",
            total: total_files,
        });
        let inferred_sources = infer_entry_point_sources_for_files_with_progress(ws, &scan_files, || {
            on_progress(AnalysisProgress::PhaseTicked);
        });
        on_progress(AnalysisProgress::PhaseFinished);
        source_hits.extend(
            inferred_sources
                .into_iter()
                .filter(|inferred| !inferred_param_subsumed_by_concrete(inferred, &concrete_param_bases)),
        );
    }
    filter_source_hits_by_metadata(
        &mut source_hits,
        pack,
        options.trust.as_deref(),
        options.category.as_deref(),
        None,
    );
    filter_by_path(ws, &mut source_hits, &options.files, &options.exclude_files);

    let include_pattern_only = options.include_pattern_only
        && options.source.is_none()
        && options.trust.is_none()
        && options.category.is_none();
    let non_taint_sink_ids: AHashSet<String> = sinks
        .iter()
        .copied()
        .filter(|rule| rule_is_non_taint_sink(rule))
        .map(|rule| rule.id.clone())
        .collect();
    let pattern_only_sink_ids: AHashSet<String> = sinks
        .iter()
        .copied()
        .filter(|rule| rule_is_pattern_only_finding(rule))
        .map(|rule| rule.id.clone())
        .collect();
    let pattern_sinks: Vec<&Rule> = if include_pattern_only {
        sinks
            .iter()
            .copied()
            .filter(|rule| pattern_only_sink_ids.contains(&rule.id))
            .collect()
    } else {
        Vec::new()
    };
    let source_languages: AHashSet<&str> = source_hits.iter().map(|hit| hit.language.as_str()).collect();
    sinks.retain(|rule| {
        !non_taint_sink_ids.contains(&rule.id) && source_languages.contains(rule.language.as_str())
    });
    sanitizers.retain(|rule| source_languages.contains(rule.language.as_str()));

    // Match endpoints over the full selected syntax scope.  A resolved-call
    // reachability slice is useful after source and sink facts are known, but
    // it is not a sound candidate filter for discovering sinks: one unresolved
    // workspace call could otherwise hide the endpoint entirely.  Matching is
    // tree-sitter/index work and the IDG performs the expensive semantic
    // narrowing below.
    let endpoint_scan_files = scan_files.clone();
    let endpoint_total_files = endpoint_scan_files.len() as u64;
    on_progress(AnalysisProgress::Note {
        label: "scope",
        detail: format!(
            "taint-analysis source_matches={} endpoint_files={} source_languages={} static_evidence={}",
            source_hits.len(),
            endpoint_scan_files.len(),
            source_languages.len(),
            static_evidence_label(options.max_precision)
        ),
    });

    on_progress(AnalysisProgress::PhaseStarted {
        label: "matching sink rules",
        total: endpoint_total_files,
    });
    // Rulepack-declared factory-method return types (`returns_type`).
    // Empty (and dormant) unless the pack ships such rules; threaded
    // into both the sink scan and the finding-time constraint re-check
    // so a `receiver_type_in` sink resolves on a factory-typed local.
    let mut sink_hits = match_rules_against_facts_for_taint_with_progress_on_files(
        ws,
        &sinks,
        &endpoint_scan_files,
        &factory_returns,
        || {
            on_progress(AnalysisProgress::PhaseTicked);
        },
    );
    on_progress(AnalysisProgress::PhaseFinished);
    let mut sanitizer_hits = gather_taint_support_matches_phased(
        ws,
        &sanitizers,
        "matching sanitizer rules",
        &endpoint_scan_files,
        endpoint_total_files,
        &factory_returns,
        &mut on_progress,
    );
    filter_by_path(ws, &mut sink_hits, &options.files, &options.exclude_files);
    filter_by_path(ws, &mut sanitizer_hits, &options.files, &options.exclude_files);
    on_progress(AnalysisProgress::Note {
        label: "scope",
        detail: format!(
            "taint-analysis sink_matches={} sanitizer_matches={} pattern_sinks={}",
            sink_hits.len(),
            sanitizer_hits.len(),
            pattern_sinks.len()
        ),
    });

    let mut pattern_sink_hits = if pattern_sinks.is_empty() {
        Vec::new()
    } else {
        gather_matches_phased(
            ws,
            &pattern_sinks,
            "matching pattern sink rules",
            &endpoint_scan_files,
            endpoint_total_files,
            &factory_returns,
            &mut on_progress,
        )
    };
    filter_by_path(ws, &mut pattern_sink_hits, &options.files, &options.exclude_files);

    // Pre-filter test-path matches when --exclude-tests is set so the
    // expensive per-source-graph + chain-build phase never even sees
    // them. Without this prune, lodash spends ~60s of interprocedural
    // work on a 27 k-line `test/test.js` IIFE before the post-hoc
    // `from_test` filter throws the findings away. Dropping the
    // matches here keeps the post-hoc filter as a safety net for
    // edge cases (cross-file flows where one side is a test path).
    if options.exclude_tests {
        let root = ws.db().workspace_root();
        source_hits.retain(|m| !path_is_excluded_with_root(root.as_deref(), &m.file, &[], true));
        sink_hits.retain(|m| !path_is_excluded_with_root(root.as_deref(), &m.file, &[], true));
        pattern_sink_hits.retain(|m| !path_is_excluded_with_root(root.as_deref(), &m.file, &[], true));
    }

    // Sort matches so the chain-aware engine sees a deterministic
    // order. `gather_matches` produces a stable-per-process order
    // but parallel match collection can interleave files
    // differently between runs; without a sort the source-frontier and
    // resulting finding fingerprints drift run-to-run
    // (`finding_ids_deterministic_across_runs`).
    sort_matches(&mut source_hits);
    sort_matches(&mut sink_hits);
    sort_matches(&mut sanitizer_hits);
    sort_matches(&mut pattern_sink_hits);

    let unattributed_source_matches = source_hits
        .iter()
        .filter(|source| func_id_for_match(ws, source).is_none())
        .count();
    let unattributed_sink_matches = sink_hits
        .iter()
        .filter(|sink| func_id_for_match(ws, sink).is_none())
        .count();
    let chain_build = build_findings_chain_aware(ChainAnalysisRequest {
        ws,
        source_hits: &source_hits,
        sinks: &sink_hits,
        sanitizers: &sanitizer_hits,
        pack,
        max_precision: options.max_precision,
        taint_graph_resident_cache_entries: options.taint_graph_resident_cache_entries,
        factory_returns: &factory_returns,
        on_progress: &mut on_progress,
    });
    let mut findings = finalize_taint_findings(
        chain_build.findings,
        TaintFindingFinalization {
            ws,
            sink_hits: &sink_hits,
            pattern_sink_hits: &pattern_sink_hits,
            pack,
            options: &options,
        },
        &mut on_progress,
    );

    hydrate_taint_flow_evidence(ws, &mut findings, options.attach_flow_evidence, &mut on_progress);

    Ok(finish_taint_analysis_report(
        findings,
        TaintReportCompletion {
            ws,
            scan_files: &scan_files,
            resolution: chain_build.resolution.as_ref(),
            unattributed_source_matches,
            unattributed_sink_matches,
            source_rule_count: sources.len(),
            sink_rule_count: selected_sink_rule_count,
            sanitizer_rule_count: sanitizers.len(),
        },
    ))
}

/// Top-level source-only enumeration. Returns every source rule match
/// in the workspace with a chain of caller frames the value could
/// flow through. Used by `bonsai security source-analysis`. No sink
/// matching; path display is sourced from propagation lineage when
/// the indexed taint graph carries it.
pub fn run_source_analysis(
    ws: &Workspace,
    pack: &Rulepack,
    options: SourceAnalysisOptions,
) -> Result<SourceAnalysisReport> {
    run_source_analysis_with_progress(ws, pack, options, |_| {})
}

/// Backwards-compatible per-file progress callback. See
/// [`run_taint_analysis_with_progress`] for the rationale; prefer
/// [`run_source_analysis_with_phase_progress`] for new callers.
pub fn run_source_analysis_with_progress<F>(
    ws: &Workspace,
    pack: &Rulepack,
    options: SourceAnalysisOptions,
    mut on_match_file_done: F,
) -> Result<SourceAnalysisReport>
where
    F: FnMut(&'static str),
{
    let mut current_label: Option<&'static str> = None;
    run_source_analysis_with_phase_progress(ws, pack, options, |event| match event {
        AnalysisProgress::PhaseStarted { label, .. } => current_label = Some(label),
        AnalysisProgress::PhaseTicked => {
            if let Some(label) = current_label {
                on_match_file_done(label);
            }
        }
        AnalysisProgress::PhaseFinished => current_label = None,
        AnalysisProgress::Note { .. } => {}
    })
}

struct SourceGraphJob {
    source_match: FindingMatch,
    start: FuncId,
    seeds: TokenSet,
    anchor: Option<Span>,
    output_arg_names: Vec<String>,
    graph_key: Vec<String>,
}

struct SourceGraphGroup {
    first_index: usize,
    start: FuncId,
    graph_key: Vec<String>,
    lineage_funcs: Option<AHashSet<FuncId>>,
    jobs: Vec<SourceGraphJob>,
}

struct SourceHitForFunction<'a> {
    index: usize,
    hit: &'a RuleMatch,
    source_match: FindingMatch,
}

fn schedule_source_graph_groups(
    ws: &Workspace,
    pack: &Rulepack,
    global: &GlobalIndex,
    source_hits: &[RuleMatch],
) -> (Vec<SourceGraphGroup>, usize) {
    let mut hits_by_func: AHashMap<FuncId, Vec<SourceHitForFunction<'_>>> = AHashMap::new();
    for (index, hit) in source_hits.iter().enumerate() {
        let Some(source_match) = source_finding_match(hit, pack) else {
            continue;
        };
        let Some(start) = func_id_for_match(ws, hit) else {
            continue;
        };
        hits_by_func.entry(start).or_default().push(SourceHitForFunction {
            index,
            hit,
            source_match,
        });
    }

    let mut hits_by_func: Vec<_> = hits_by_func.into_iter().collect();
    hits_by_func.sort_by_key(|(func, hits)| {
        (
            global
                .declaring_file(SymbolId::new(func.raw()))
                .map_or(u32::MAX, FileId::raw),
            hits.first().map(|hit| hit.index).unwrap_or(usize::MAX),
        )
    });
    let source_function_count = hits_by_func.len();

    let mut source_jobs = Vec::new();
    let mut active_file = None;
    let mut active_index = None;
    for (start, hits) in hits_by_func {
        let Some(file) = global.declaring_file(SymbolId::new(start.raw())) else {
            continue;
        };
        if active_file != Some(file) {
            active_index = ws.exact_decl_index_shared(file);
            active_file = Some(file);
        }
        let Some(decl) = active_index
            .as_ref()
            .and_then(|index| index.defs.iter().find(|decl| decl.symbol.raw() == start.raw()))
        else {
            continue;
        };
        for hit in hits {
            let seeds = source_seed_set(pack, hit.hit, decl);
            let output_arg_names = output_arg_names_for_match(pack, hit.hit, decl);
            let anchor = source_anchor_for_rule_match(pack, hit.hit);
            let graph_key = sorted_seed_key_with_anchor(&seeds, anchor, &output_arg_names);
            source_jobs.push((
                hit.index,
                SourceGraphJob {
                    source_match: hit.source_match,
                    start,
                    seeds,
                    anchor,
                    output_arg_names,
                    graph_key,
                },
            ));
        }
    }
    source_jobs.sort_by_key(|(index, _)| *index);

    let mut source_groups: Vec<SourceGraphGroup> = Vec::new();
    let mut group_by_key: AHashMap<(FuncId, Vec<String>), usize> = AHashMap::new();
    for (index, job) in source_jobs {
        let group_key = (job.start, job.graph_key.clone());
        if let Some(&group_index) = group_by_key.get(&group_key) {
            source_groups[group_index].jobs.push(job);
        } else {
            let group_index = source_groups.len();
            group_by_key.insert(group_key, group_index);
            source_groups.push(SourceGraphGroup {
                first_index: index,
                start: job.start,
                graph_key: job.graph_key.clone(),
                lineage_funcs: None,
                jobs: vec![job],
            });
        }
    }
    source_groups.sort_by_key(|group| group.first_index);
    (source_groups, source_function_count)
}

struct SourceLineageCompilationContext<'a> {
    ws: &'a Workspace,
    pack: &'a Rulepack,
    global: &'a GlobalIndex,
    transfer_languages: &'a AHashSet<String>,
    graph_config: &'a InterTaintConfig,
    transfer_options: &'a bonsai_idg::TransferOptions,
    caches: &'a InterTaintCaches,
}

struct SourceLineageScope {
    graph: SourceLineageGraph,
    cache_persist_started: bool,
}

enum SourceLineageGraph {
    Empty,
    Compiled {
        idg: Arc<bonsai_idg::IdgQueryService>,
        resolution: ResolutionCoverage,
    },
}

impl SourceLineageScope {
    fn resolution(&self) -> Option<&ResolutionCoverage> {
        match &self.graph {
            SourceLineageGraph::Empty => None,
            SourceLineageGraph::Compiled { resolution, .. } => Some(resolution),
        }
    }
}

fn compile_source_lineage_scope<F>(
    context: &SourceLineageCompilationContext<'_>,
    source_groups: &mut [SourceGraphGroup],
    on_progress: &mut F,
) -> SourceLineageScope
where
    F: FnMut(AnalysisProgress),
{
    if source_groups.is_empty() {
        let fingerprint = taint_cache::scoped_config_fingerprint(
            context.pack,
            "source-analysis",
            context.graph_config.max_edge_precision,
            &[],
            &[],
            context.transfer_options.semantic_fingerprint(),
        );
        let cache_report = taint_cache::prepare_workspace_cache(context.ws, "source-analysis", fingerprint);
        on_progress(AnalysisProgress::Note {
            label: "taint-cache",
            detail: cache_report.detail(),
        });
        return SourceLineageScope {
            graph: SourceLineageGraph::Empty,
            cache_persist_started: cache_report.persist_started,
        };
    }

    on_progress(AnalysisProgress::PhaseStarted {
        label: "building source lineage scope",
        total: source_groups.len() as u64 + 2,
    });
    let mut source_starts: Vec<FuncId> = source_groups.iter().map(|group| group.start).collect();
    source_starts.sort_by_key(|func| func.raw());
    source_starts.dedup();
    let reachable_call_graph = context.ws.source_reachable_resolved_call_graph(
        &source_starts,
        &[],
        context.graph_config.max_edge_precision,
    );
    let source_call_graph = reachable_call_graph.graph;
    let resolution = ResolutionCoverage::from_graph(source_call_graph.as_ref(), reachable_call_graph.funcs);
    context
        .caches
        .seed_resolved_call_graph(source_call_graph.as_ref());
    on_progress(AnalysisProgress::PhaseTicked);

    let mut scoped_func_set: AHashSet<FuncId> = AHashSet::default();
    let mut lineage_scope_by_start: AHashMap<FuncId, AHashSet<FuncId>> = AHashMap::default();
    for group in source_groups {
        let source_lineage_funcs = lineage_scope_by_start
            .entry(group.start)
            .or_insert_with(|| {
                source_analysis_lineage_func_scope(
                    group.start,
                    context.global,
                    source_call_graph.as_ref(),
                    context.graph_config.max_edge_precision,
                )
            })
            .clone();
        append_taint_target_key(
            &mut group.graph_key,
            "source_lineage",
            Some(&source_lineage_funcs),
        );
        scoped_func_set.extend(source_lineage_funcs.iter().copied());
        group.lineage_funcs = Some(source_lineage_funcs);
        on_progress(AnalysisProgress::PhaseTicked);
    }

    let mut scoped_funcs: Vec<FuncId> = scoped_func_set.into_iter().collect();
    scoped_funcs.sort_by_key(|func| func.raw());
    scoped_funcs.dedup();
    let mut scoped_files: Vec<FileId> = scoped_funcs
        .iter()
        .filter_map(|func| context.global.declaring_file(SymbolId::new(func.raw())))
        .collect();
    scoped_files.sort_by_key(|file| file.raw());
    scoped_files.dedup();
    let fingerprint = taint_cache::scoped_config_fingerprint(
        context.pack,
        "source-analysis",
        context.graph_config.max_edge_precision,
        &scoped_files,
        &scoped_funcs,
        context.transfer_options.semantic_fingerprint(),
    );
    let cache_report = taint_cache::prepare_workspace_cache(context.ws, "source-analysis", fingerprint);
    on_progress(AnalysisProgress::Note {
        label: "taint-cache",
        detail: cache_report.detail(),
    });
    ensure_workspace_files_indexed(context.ws, &scoped_files);
    let idg = seed_idg_service_for_rulepack_for_files(
        context.ws,
        context.pack,
        context.transfer_languages,
        &scoped_files,
        &scoped_funcs,
        source_call_graph.as_ref(),
    );
    on_progress(AnalysisProgress::PhaseTicked);
    on_progress(AnalysisProgress::PhaseFinished);
    SourceLineageScope {
        graph: SourceLineageGraph::Compiled { idg, resolution },
        cache_persist_started: cache_report.persist_started,
    }
}

struct SourceLineageEnumerationContext<'a> {
    ws: &'a Workspace,
    global: &'a bonsai_index::GlobalIndex,
    idg: &'a bonsai_idg::IdgQueryService,
    graph_config: &'a InterTaintConfig,
    caches: &'a InterTaintCaches,
    lineage_limits: SourceLineageLimits,
}

fn build_source_group_candidates(
    context: &SourceLineageEnumerationContext<'_>,
    group: &SourceGraphGroup,
) -> Vec<SourceAnalysisCandidate> {
    let graph = context
        .ws
        .taint_index()
        .get(group.start, &group.graph_key)
        .unwrap_or_else(|| {
            let first = &group.jobs[0];
            let graph = Arc::new(bonsai_taint::entry_taint_call_records_from_idg_query(
                bonsai_taint::IdgTaintQuery::semantic(
                    bonsai_taint::IdgTaintSource::rule_match(
                        group.start,
                        &first.seeds,
                        first.anchor,
                        &first.output_arg_names,
                    ),
                    context.ws.db(),
                    context.idg,
                )
                .with_global_index(context.global)
                .with_transfers(bonsai_taint::IdgTaintTransfers {
                    call_result_passthroughs: &context.graph_config.call_result_passthroughs,
                    call_results_materialized: true,
                    ..bonsai_taint::IdgTaintTransfers::none()
                })
                .with_targets(bonsai_taint::IdgTaintTargets {
                    nodes: None,
                    funcs: group.lineage_funcs.as_ref(),
                    lineage_funcs: group.lineage_funcs.as_ref(),
                    relevance: None,
                })
                .with_max_precision(context.graph_config.max_edge_precision)
                .with_caches(context.caches),
            ));
            context
                .ws
                .taint_index()
                .insert_if_absent(group.start, group.graph_key.clone(), graph)
        });

    let mut candidates = Vec::new();
    for job in &group.jobs {
        let mut seen_chains: AHashSet<Vec<String>> = AHashSet::new();
        let (lineages, lineage_stats) = collect_tainted_source_lineages(
            &graph.call_records,
            job.start,
            context.lineage_limits.max_hops,
            context.lineage_limits.max_paths,
        );
        let mut emitted_lineage_rows = 0usize;
        for emission in &lineages {
            let terminal = emission
                .records
                .last()
                .map(|record| record.callee)
                .unwrap_or(job.start);
            let Some(path) = chain_funcs_for_lineage(&emission.records, job.start, terminal) else {
                continue;
            };
            let Some(chain_names) = chain_names_for_path(context.ws, &path) else {
                continue;
            };
            if !seen_chains.insert(chain_names.clone()) {
                continue;
            }
            let taint_path = taint_path_for_lineage(context.ws, &emission.records, None);
            let flow_id = flow_id_for_taint_path(&chain_names, &taint_path);
            let precision = chain_precision_for_records(&emission.records);
            if !precision.is_semantic() {
                continue;
            }
            candidates.push(SourceAnalysisCandidate {
                source: job.source_match.clone(),
                path,
                flow_id,
                chain_names,
                taint_path,
                precision,
                lineage: SourceLineageStatus::from_lineage(emission, lineage_stats, emitted_lineage_rows),
            });
            emitted_lineage_rows = emitted_lineage_rows.saturating_add(1);
        }
        if lineages.is_empty() {
            let path = vec![job.start];
            let Some(chain_names) = chain_names_for_path(context.ws, &path) else {
                continue;
            };
            let taint_path = Vec::new();
            let flow_id = flow_id_for_taint_path(&chain_names, &taint_path);
            candidates.push(SourceAnalysisCandidate {
                source: job.source_match.clone(),
                path,
                flow_id,
                chain_names,
                taint_path,
                precision: Precision::Exact,
                lineage: SourceLineageStatus::complete(),
            });
        }
    }
    candidates
}

fn canonicalize_source_candidates(
    parallel_candidates: Vec<SourceAnalysisCandidate>,
) -> Vec<SourceAnalysisCandidate> {
    // Key on the rendered identity `(source-site, displayed-chain)`, not
    // `flow_id`: path detail that is not displayed must not create duplicate
    // report rows. The first call-graph-ordered candidate remains canonical.
    let mut seen: AHashMap<(String, String, u32, u32, String), usize> = AHashMap::new();
    let mut candidates: Vec<SourceAnalysisCandidate> = Vec::with_capacity(parallel_candidates.len());
    for candidate in parallel_candidates {
        let dedupe_key = (
            candidate.source.rule_id.clone(),
            candidate.source.file.clone(),
            candidate.source.line,
            candidate.source.column,
            displayed_chain_key(&candidate.chain_names),
        );
        if let Some(&index) = seen.get(&dedupe_key) {
            merge_source_lineage_status(&mut candidates[index].lineage, candidate.lineage);
            candidates[index].precision = candidates[index].precision.meet(candidate.precision);
        } else {
            let index = candidates.len();
            seen.insert(dedupe_key, index);
            candidates.push(candidate);
        }
    }
    candidates
}

fn enumerate_source_candidates<F>(
    context: &SourceLineageEnumerationContext<'_>,
    source_groups: &[SourceGraphGroup],
    total_source_path_ticks: usize,
    on_progress: &mut F,
) -> Vec<SourceAnalysisCandidate>
where
    F: FnMut(AnalysisProgress),
{
    on_progress(AnalysisProgress::PhaseStarted {
        label: "enumerating source paths",
        total: total_source_path_ticks as u64,
    });
    use rayon::prelude::*;
    let worker_count = source_analysis_worker_count();
    let mut grouped_candidates: Vec<(usize, Vec<SourceAnalysisCandidate>)> =
        if worker_count > 1 && source_groups.len() > 1 {
            match rayon::ThreadPoolBuilder::new().num_threads(worker_count).build() {
                Ok(pool) => {
                    let (tx, rx) = mpsc::channel();
                    let mut groups = None;
                    std::thread::scope(|scope| {
                        let worker = scope.spawn(|| {
                            pool.install(|| {
                                source_groups
                                    .par_iter()
                                    .enumerate()
                                    .map(|(index, group)| {
                                        let candidates = build_source_group_candidates(context, group);
                                        let _ = tx.send(group.jobs.len());
                                        (index, candidates)
                                    })
                                    .collect()
                            })
                        });
                        let mut completed = 0usize;
                        while completed < total_source_path_ticks {
                            match rx.recv_timeout(Duration::from_millis(250)) {
                                Ok(ticks) => {
                                    for _ in 0..ticks {
                                        completed = completed.saturating_add(1);
                                        on_progress(AnalysisProgress::PhaseTicked);
                                    }
                                }
                                Err(mpsc::RecvTimeoutError::Timeout) => {
                                    if worker.is_finished() {
                                        break;
                                    }
                                }
                                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                            }
                        }
                        groups = Some(match worker.join() {
                            Ok(result) => result,
                            Err(payload) => std::panic::resume_unwind(payload),
                        });
                        while completed < total_source_path_ticks {
                            on_progress(AnalysisProgress::PhaseTicked);
                            completed += 1;
                        }
                    });
                    groups.unwrap_or_default()
                }
                Err(_) => source_groups
                    .iter()
                    .enumerate()
                    .map(|(index, group)| {
                        let candidates = build_source_group_candidates(context, group);
                        for _ in 0..group.jobs.len() {
                            on_progress(AnalysisProgress::PhaseTicked);
                        }
                        (index, candidates)
                    })
                    .collect(),
            }
        } else {
            source_groups
                .iter()
                .enumerate()
                .map(|(index, group)| {
                    let candidates = build_source_group_candidates(context, group);
                    for _ in 0..group.jobs.len() {
                        on_progress(AnalysisProgress::PhaseTicked);
                    }
                    (index, candidates)
                })
                .collect()
        };
    grouped_candidates.sort_by_key(|(index, _)| *index);
    let parallel_candidates = grouped_candidates
        .into_iter()
        .flat_map(|(_, candidates)| candidates)
        .collect();
    let candidates = canonicalize_source_candidates(parallel_candidates);
    let emitted_ticks: usize = source_groups.iter().map(|group| group.jobs.len()).sum();
    for _ in emitted_ticks..total_source_path_ticks {
        on_progress(AnalysisProgress::PhaseTicked);
    }
    on_progress(AnalysisProgress::PhaseFinished);
    candidates
}

/// Phase-aware variant of [`run_source_analysis_with_progress`].
pub fn run_source_analysis_with_phase_progress<F>(
    ws: &Workspace,
    pack: &Rulepack,
    options: SourceAnalysisOptions,
    mut on_progress: F,
) -> Result<SourceAnalysisReport>
where
    F: FnMut(AnalysisProgress),
{
    let _taint_analysis_guard = ws.lock_taint_analysis();
    let _dependency_package_snapshot = ws.db().workspace_root().map(|root| {
        crate::deps::begin_workspace_dependency_package_snapshot(&root, ws.db().vfs().instance_id())
    });
    let _ = crate::matcher::drain_runtime_disabled_rules();
    let mut sources = select_rules(pack, RuleKind::Source, None, options.source.as_deref(), |r| {
        source_rule_matches_filters(
            r,
            options.trust.as_deref(),
            options.category.as_deref(),
            options.tag.as_deref(),
        )
    })?;
    filter_rules_to_workspace_languages(ws, &mut sources);
    let factory_returns = crate::matcher::build_factory_returns(&pack.all_rules());

    let scan_files = security_scan_files(ws, &options.files, &options.exclude_files, options.exclude_tests);
    let total_files = scan_files.len() as u64;
    on_progress(AnalysisProgress::Note {
        label: "scope",
        detail: format!(
            "source-analysis files={} source_rules={} include_inferred_sources={} exclude_tests={} file_filters={} exclude_filters={}",
            scan_files.len(),
            sources.len(),
            options.include_inferred_sources,
            options.exclude_tests,
            options.files.len(),
            options.exclude_files.len()
        ),
    });
    let mut source_hits = gather_matches_phased(
        ws,
        &sources,
        "matching source rules",
        &scan_files,
        total_files,
        &factory_returns,
        &mut on_progress,
    );
    // Opt-in synthetic per-function entry-point sources (see TaintAnalysisOptions).
    if options.include_inferred_sources {
        // Concrete rulepack source matches gathered above are precise,
        // resolver-backed evidence. A broad inferred entry-point param
        // source is redundant noise when a concrete source in the same
        // function is rooted at that same parameter — e.g. Go's
        // `entry-point.unreferenced_entry.param_1` for `r` duplicates the
        // concrete `r.URL.Query().Get(...)` query-value source on the same
        // request param. Drop the inferred param in that case so the
        // precise source is the sole evidence for the flow.
        let concrete_param_bases = concrete_source_param_bases(pack, &source_hits);
        on_progress(AnalysisProgress::PhaseStarted {
            label: "inferring entry-point sources",
            total: total_files,
        });
        let inferred_sources = infer_entry_point_sources_for_files_with_progress(ws, &scan_files, || {
            on_progress(AnalysisProgress::PhaseTicked);
        });
        on_progress(AnalysisProgress::PhaseFinished);
        source_hits.extend(
            inferred_sources
                .into_iter()
                .filter(|inferred| !inferred_param_subsumed_by_concrete(inferred, &concrete_param_bases)),
        );
    }
    if let Some(source) = options.source.as_deref() {
        // CLI `--source <regex>` filter — match rule id directly, or
        // any alias the rule advertises (covers vendor-renames and
        // cross-language convenience aliases).
        let source_re = Regex::new(source)
            .map_err(|error| anyhow::anyhow!("invalid source regex `{source}`: {error}"))?;
        source_hits.retain(|hit| {
            source_re.is_match(&hit.rule_id)
                || pack
                    .find_rule_by_id(&hit.rule_id)
                    .is_some_and(|rule| rule.aliases.iter().any(|alias| source_re.is_match(alias)))
        });
    }
    filter_source_hits_by_metadata(
        &mut source_hits,
        pack,
        options.trust.as_deref(),
        options.category.as_deref(),
        options.tag.as_deref(),
    );
    filter_by_path(ws, &mut source_hits, &options.files, &options.exclude_files);
    if options.exclude_tests {
        let root = ws.db().workspace_root();
        source_hits.retain(|m| !path_is_test_file_with_root(root.as_deref(), &m.file));
    }
    sort_matches(&mut source_hits);
    let unattributed_source_matches = source_hits
        .iter()
        .filter(|source| func_id_for_match(ws, source).is_none())
        .count();
    on_progress(AnalysisProgress::Note {
        label: "scope",
        detail: format!("source-analysis source_matches={}", source_hits.len()),
    });

    let global = ws.compiler_linkage_index();
    let transfer_languages = workspace_languages(ws);
    let source_graph_config = InterTaintConfig {
        clean_output_overwrites: clean_output_overwrites_from_rulepack_for_languages(
            pack,
            &transfer_languages,
        ),
        source_output_args: source_output_args_from_rulepack_for_languages(pack, &transfer_languages),
        source_callback_args: source_callback_args_from_rulepack_for_languages(pack, &transfer_languages),
        call_result_passthroughs: call_result_passthroughs_from_rulepack_for_languages(
            pack,
            &transfer_languages,
        ),
        output_arg_flows: output_arg_flows_from_rulepack_for_languages(pack, &transfer_languages),
        receiver_state_propagations: receiver_state_propagations_from_rulepack_for_languages(
            pack,
            &transfer_languages,
        ),
        max_edge_precision: Some(Precision::Narrowed),
    };
    // Exact source-seeded graphs are cached through the workspace
    // `TaintGraphIndex`, which is bounded in memory and keyed by a
    // rule/config fingerprint. Disk persistence is best-effort and
    // default-on so repeated CLI runs can stay warm; set
    // `BONSAI_TAINT_GRAPH_PERSIST=0` to disable the performance
    // artifact without changing analysis results.
    let source_graph_caches = ws.inter_taint_caches();
    let mut source_idg_transfer_options = idg_transfer_options_from_rulepack_shapes(
        &source_graph_config.clean_output_overwrites,
        &source_graph_config.source_output_args,
        &source_graph_config.source_callback_args,
        &source_graph_config.output_arg_flows,
        &source_graph_config.receiver_state_propagations,
    );
    source_idg_transfer_options.call_result_passthroughs =
        idg_call_result_passthrough_specs(&source_graph_config.call_result_passthroughs);
    let (mut source_groups, source_function_count) =
        schedule_source_graph_groups(ws, pack, global.as_ref(), &source_hits);
    on_progress(AnalysisProgress::Note {
        label: "scope",
        detail: format!(
            "source-analysis source_jobs={} source_graph_groups={} functions={}",
            source_groups.iter().map(|group| group.jobs.len()).sum::<usize>(),
            source_groups.len(),
            source_function_count
        ),
    });
    let source_scope = compile_source_lineage_scope(
        &SourceLineageCompilationContext {
            ws,
            pack,
            global: global.as_ref(),
            transfer_languages: &transfer_languages,
            graph_config: &source_graph_config,
            transfer_options: &source_idg_transfer_options,
            caches: source_graph_caches,
        },
        &mut source_groups,
        &mut on_progress,
    );
    let mut candidates = match &source_scope.graph {
        SourceLineageGraph::Empty => {
            debug_assert!(source_groups.is_empty());
            on_progress(AnalysisProgress::PhaseStarted {
                label: "enumerating source paths",
                total: source_hits.len() as u64,
            });
            for _ in 0..source_hits.len() {
                on_progress(AnalysisProgress::PhaseTicked);
            }
            on_progress(AnalysisProgress::PhaseFinished);
            Vec::new()
        }
        SourceLineageGraph::Compiled { idg, .. } => enumerate_source_candidates(
            &SourceLineageEnumerationContext {
                ws,
                global: global.as_ref(),
                idg,
                graph_config: &source_graph_config,
                caches: source_graph_caches,
                lineage_limits: options.lineage_limits,
            },
            &source_groups,
            source_hits.len(),
            &mut on_progress,
        ),
    };

    if !options.exclude_files.is_empty() || options.exclude_tests {
        candidates.retain(|candidate| {
            !source_candidate_has_excluded_path(ws, candidate, &options.exclude_files, options.exclude_tests)
        });
    }
    let candidates = combine_source_analysis_candidates(candidates);
    let lineage_summary = SourceLineageSummary::from_candidates(&candidates);
    let runtime_disabled_rules = crate::matcher::drain_runtime_disabled_rules();
    let mut analysis_incomplete_reasons: BTreeSet<String> =
        workspace_analysis_incomplete_reasons(ws, &scan_files, source_scope.resolution())
            .into_iter()
            .collect();
    if unattributed_source_matches > 0 {
        analysis_incomplete_reasons.insert(format!(
            "unattributed-source-matches:{unattributed_source_matches}"
        ));
    }
    if !runtime_disabled_rules.is_empty() {
        analysis_incomplete_reasons
            .insert(format!("runtime-disabled-rules:{}", runtime_disabled_rules.len()));
    }
    if lineage_summary.incomplete_flows > 0 {
        analysis_incomplete_reasons.insert(format!(
            "incomplete-source-lineage-flows:{}",
            lineage_summary.incomplete_flows
        ));
    }
    if lineage_summary.truncated_hop_flows > 0 {
        analysis_incomplete_reasons.insert(format!(
            "source-lineage-truncated-hop-flows:{}",
            lineage_summary.truncated_hop_flows
        ));
    }
    if lineage_summary.omitted_paths > 0 {
        analysis_incomplete_reasons.insert(format!(
            "source-lineage-omitted-paths:{}",
            lineage_summary.omitted_paths
        ));
    }
    let analysis_incomplete_reasons: Vec<String> = analysis_incomplete_reasons.into_iter().collect();
    finish_taint_cache_write_through(ws, source_scope.cache_persist_started, &mut on_progress);
    Ok(SourceAnalysisReport {
        candidates,
        source_rule_count: sources.len(),
        lineage_summary,
        analysis_complete: analysis_incomplete_reasons.is_empty(),
        analysis_incomplete_reasons,
        runtime_disabled_rules,
    })
}

/// Pick rules from the pack matching `want_kind` and the supplied
/// filters. Aliases are considered alongside ids so vendor-renamed
/// rules (`python.cmdi.os_system` aliased as `python.cmdi.system`)
/// still resolve. The `extra` closure layers caller-specific
/// predicates (severity floor, trust filter, etc.).
pub fn select_rules<'a, F>(
    pack: &'a Rulepack,
    want_kind: RuleKind,
    exact: Option<&str>,
    regex: Option<&str>,
    extra: F,
) -> Result<Vec<&'a Rule>>
where
    F: Fn(&Rule) -> bool,
{
    let compiled_regex = regex
        .map(|pattern| {
            Regex::new(pattern).map_err(|err| anyhow::anyhow!("invalid rule regex `{pattern}`: {err}"))
        })
        .transpose()?;
    Ok(pack
        .all_rules()
        .into_iter()
        .filter(|rule| rule.kind == want_kind && rule.enabled)
        .filter(|rule| exact.is_none_or(|id| rule.id == id || rule.aliases.iter().any(|alias| alias == id)))
        .filter(|rule| {
            compiled_regex.as_ref().is_none_or(|regex| {
                regex.is_match(&rule.id) || rule.aliases.iter().any(|alias| regex.is_match(alias))
            })
        })
        .filter(|rule| extra(rule))
        .collect())
}

/// Drop rules whose language isn't represented in the workspace.
/// Avoids paying matcher overhead for rules that can never fire on
/// the current file set.
pub fn filter_rules_to_workspace_languages<'a>(ws: &Workspace, rules: &mut Vec<&'a Rule>) {
    let languages = workspace_languages(ws);
    if languages.is_empty() {
        // Empty workspace — drop all rules so downstream code knows
        // there's nothing to analyse.
        rules.clear();
        return;
    }
    rules.retain(|rule| languages.contains(rule.language.as_str()));
}

/// Distinct language ids the workspace's adapter pool covers.
/// Cheap O(files) scan; callers that need this repeatedly should
/// cache the result.
pub fn workspace_languages(ws: &Workspace) -> AHashSet<String> {
    let mut languages = AHashSet::new();
    for file in ws.db().vfs().all_files() {
        if let Some(adapter) = ws.db().adapter_for(file) {
            languages.insert(adapter.language_id().as_str().to_string());
        }
    }
    languages
}

pub fn source_inventory(
    ws: &Workspace,
    pack: &Rulepack,
    options: SecurityInventoryOptions,
) -> Result<Vec<RuleMatch>> {
    source_inventory_with_progress(ws, pack, options, |_| {})
}

pub fn source_inventory_with_progress<F>(
    ws: &Workspace,
    pack: &Rulepack,
    options: SecurityInventoryOptions,
    mut on_progress: F,
) -> Result<Vec<RuleMatch>>
where
    F: FnMut(AnalysisProgress),
{
    let mut selected = select_rules(
        pack,
        RuleKind::Source,
        options.rule.as_deref(),
        options.rule_regex.as_deref(),
        |rule| {
            source_rule_matches_filters(
                rule,
                options.trust.as_deref(),
                options.category.as_deref(),
                options.tag.as_deref(),
            ) && options
                .severity
                .is_none_or(|min| rule.severity.is_some_and(|severity| severity >= min))
        },
    )?;
    filter_rules_to_workspace_languages(ws, &mut selected);
    let scan_files = security_scan_files(ws, &options.files, &options.exclude_files, false);
    let total_files = scan_files.len() as u64;
    let factory_returns = crate::matcher::build_factory_returns(&pack.all_rules());
    let mut matches = gather_inventory_matches_phased(
        ws,
        &selected,
        "matching source rules",
        &scan_files,
        total_files,
        &factory_returns,
        &mut on_progress,
    );
    on_progress(AnalysisProgress::PhaseStarted {
        label: "finalizing matches",
        total: 0,
    });
    filter_by_path(ws, &mut matches, &options.files, &options.exclude_files);
    sort_matches(&mut matches);
    dedup_inventory_matches(&mut matches);
    on_progress(AnalysisProgress::PhaseFinished);
    Ok(matches)
}

pub fn sink_inventory(
    ws: &Workspace,
    pack: &Rulepack,
    options: SecurityInventoryOptions,
) -> Result<Vec<RuleMatch>> {
    sink_inventory_with_progress(ws, pack, options, |_| {})
}

pub fn sink_inventory_with_progress<F>(
    ws: &Workspace,
    pack: &Rulepack,
    options: SecurityInventoryOptions,
    mut on_progress: F,
) -> Result<Vec<RuleMatch>>
where
    F: FnMut(AnalysisProgress),
{
    let mut selected = select_rules(
        pack,
        RuleKind::Sink,
        options.rule.as_deref(),
        options.rule_regex.as_deref(),
        |rule| {
            options
                .severity
                .is_none_or(|min| rule.severity.is_some_and(|severity| severity >= min))
                && options
                    .tag
                    .as_deref()
                    .is_none_or(|tag| rule.tag.as_deref() == Some(tag))
                // `category` filter mirrors `select_pack_rules` for
                // parity with the CLI: match tag, canonical family,
                // or raw family abbreviation. See
                // `rule_matches_category`.
                && options
                    .category
                    .as_deref()
                    .is_none_or(|category| rule_matches_category(rule, category))
        },
    )?;
    filter_rules_to_workspace_languages(ws, &mut selected);
    let scan_files = security_scan_files(ws, &options.files, &options.exclude_files, false);
    let factory_returns = crate::matcher::build_factory_returns(&pack.all_rules());
    on_progress(AnalysisProgress::PhaseStarted {
        label: "matching sink rules",
        total: scan_files.len() as u64,
    });
    let mut matches = match_rules_against_facts_for_sink_inventory_with_progress_on_files(
        ws,
        &selected,
        &scan_files,
        &factory_returns,
        || on_progress(AnalysisProgress::PhaseTicked),
    );
    on_progress(AnalysisProgress::PhaseFinished);
    on_progress(AnalysisProgress::PhaseStarted {
        label: "finalizing matches",
        total: 0,
    });
    filter_by_path(ws, &mut matches, &options.files, &options.exclude_files);
    sort_matches(&mut matches);
    dedup_inventory_matches(&mut matches);
    on_progress(AnalysisProgress::PhaseFinished);
    Ok(matches)
}

pub fn sanitizer_inventory(
    ws: &Workspace,
    pack: &Rulepack,
    options: SecurityInventoryOptions,
) -> Result<Vec<RuleMatch>> {
    sanitizer_inventory_with_progress(ws, pack, options, |_| {})
}

pub fn sanitizer_inventory_with_progress<F>(
    ws: &Workspace,
    pack: &Rulepack,
    options: SecurityInventoryOptions,
    mut on_progress: F,
) -> Result<Vec<RuleMatch>>
where
    F: FnMut(AnalysisProgress),
{
    let mut selected = select_rules(
        pack,
        RuleKind::Sanitizer,
        options.rule.as_deref(),
        options.rule_regex.as_deref(),
        |rule| {
            options
                .tag
                .as_deref()
                .is_none_or(|tag| rule.tag.as_deref() == Some(tag))
                // Honor `severity` and `category` for parity with
                // sink_inventory and select_pack_rules — sanitizer
                // rules can carry severity (escalated review for
                // "weak hash" tags etc.).
                && options
                    .severity
                    .is_none_or(|min| rule.severity.is_some_and(|severity| severity >= min))
                && options
                    .category
                    .as_deref()
                    .is_none_or(|category| rule_matches_category(rule, category))
        },
    )?;
    filter_rules_to_workspace_languages(ws, &mut selected);
    let scan_files = security_scan_files(ws, &options.files, &options.exclude_files, false);
    let total_files = scan_files.len() as u64;
    let factory_returns = crate::matcher::build_factory_returns(&pack.all_rules());
    let mut matches = gather_inventory_matches_phased(
        ws,
        &selected,
        "matching sanitizer rules",
        &scan_files,
        total_files,
        &factory_returns,
        &mut on_progress,
    );
    on_progress(AnalysisProgress::PhaseStarted {
        label: "finalizing matches",
        total: 0,
    });
    filter_by_path(ws, &mut matches, &options.files, &options.exclude_files);
    sort_matches(&mut matches);
    dedup_inventory_matches(&mut matches);
    on_progress(AnalysisProgress::PhaseFinished);
    Ok(matches)
}

pub fn dependency_inventory(
    ws: &Workspace,
    pack: &Rulepack,
    root: &Path,
    options: DependencyInventoryOptions,
) -> DependencyInventory {
    let mut inv = build_inventory(pack, ws, root);
    if let Some(framework) = options.framework.as_deref() {
        inv.rows.retain(|row| {
            row.key == framework || row.signals.iter().any(|signal| signal.contains(framework))
        });
    }
    if let Some(severity) = options.severity {
        inv.rows
            .retain(|row| row.severity.is_some_and(|row_severity| row_severity >= severity));
    }
    let filter_root = ws.db().workspace_root();
    if !options.files.is_empty() {
        inv.rows.retain(|row| {
            row.evidence_files.iter().any(|evidence| {
                options
                    .files
                    .iter()
                    .any(|file| path_filter_matches_with_root(filter_root.as_deref(), evidence, file))
            })
        });
    }
    if !options.exclude_files.is_empty() {
        inv.rows.retain(|row| {
            !row.evidence_files.iter().any(|evidence| {
                options
                    .exclude_files
                    .iter()
                    .any(|file| path_filter_matches_with_root(filter_root.as_deref(), evidence, file))
            })
        });
    }
    inv.rows
        .sort_by(|a, b| (a.language.as_str(), a.key.as_str()).cmp(&(b.language.as_str(), b.key.as_str())));
    inv
}

/// Decorate raw matcher hits with rule metadata (tag, severity, CWE,
/// frameworks, etc.) so renderers don't have to look up rules
/// themselves. Used by `bonsai security {sources,sinks,sanitizers}`.
pub fn security_match_rows(pack: &Rulepack, matches: &[RuleMatch]) -> Vec<SecurityMatchRow> {
    matches
        .iter()
        .map(|rule_match| {
            let rule = pack.find_rule_by_id(&rule_match.rule_id);
            SecurityMatchRow {
                rule_id: rule_match.rule_id.clone(),
                tag: rule.and_then(|rule| rule.tag.clone()),
                severity: rule.and_then(|rule| rule.severity.map(|severity| severity.as_str().to_string())),
                category: rule.and_then(|rule| rule.category.clone()),
                trust: rule
                    .and_then(|rule| rule.trust)
                    .map(|trust| trust.as_str().to_string()),
                cwe: rule.map(|rule| rule.cwe.clone()).unwrap_or_default(),
                owasp: rule.map(|rule| rule.owasp.clone()).unwrap_or_default(),
                frameworks: rule.map(|rule| rule.frameworks.clone()).unwrap_or_default(),
                packages: rule.map(|rule| rule.packages.clone()).unwrap_or_default(),
                language: rule_match.language.clone(),
                file: rule_match.file.clone(),
                line: rule_match.line,
                column: rule_match.column,
                text: rule_match.match_text.clone(),
                enclosing_fn: rule_match.enclosing_fn.clone(),
                description: rule.map(|rule| rule.description.clone()),
            }
        })
        .collect()
}

pub fn pack_inventory(pack: &Rulepack, options: PackInventoryOptions) -> Vec<PackRuleRow> {
    select_pack_rules(pack, &options)
        .into_iter()
        .map(|rule| PackRuleRow {
            rule_id: rule.id.clone(),
            language: rule.language.clone(),
            kind: rule_kind_str(rule.kind).to_string(),
            family: rule_family(&rule.id).to_string(),
            tag: rule.tag.clone(),
            severity: rule.severity.map(|severity| severity.as_str().to_string()),
            enabled: rule.enabled,
            packages: rule.packages.clone(),
            frameworks: rule.frameworks.clone(),
            description: rule.description.clone(),
        })
        .collect()
}

pub fn pack_audit(pack: &Rulepack, lang_filter: Option<&str>) -> PackAuditReport {
    type Counts = AHashMap<(String, String), (u32, u32)>;
    let mut sink_counts: Counts = AHashMap::new();
    let mut source_counts: AHashMap<String, (u32, u32)> = AHashMap::new();
    let mut sanitizer_counts: AHashMap<String, (u32, u32)> = AHashMap::new();
    let mut langs: AHashSet<String> = AHashSet::new();

    for rule in pack.all_rules() {
        if lang_filter.is_some_and(|lang| rule.language != lang) {
            continue;
        }
        langs.insert(rule.language.clone());
        match rule.kind {
            RuleKind::Sink => {
                let mut families: BTreeSet<String> = BTreeSet::new();
                families.insert(rule_family(&rule.id).to_string());
                for alias in &rule.aliases {
                    families.insert(rule_family(alias).to_string());
                }
                for family in families {
                    let entry = sink_counts
                        .entry((rule.language.clone(), family))
                        .or_insert((0, 0));
                    if rule.enabled {
                        entry.0 += 1;
                    } else {
                        entry.1 += 1;
                    }
                }
            }
            RuleKind::Source => {
                let entry = source_counts.entry(rule.language.clone()).or_insert((0, 0));
                if rule.enabled {
                    entry.0 += 1;
                } else {
                    entry.1 += 1;
                }
            }
            RuleKind::Sanitizer => {
                let entry = sanitizer_counts.entry(rule.language.clone()).or_insert((0, 0));
                if rule.enabled {
                    entry.0 += 1;
                } else {
                    entry.1 += 1;
                }
            }
            // Typing-only rules are not part of the source/sink/sanitizer
            // inventory — they only feed factory-return resolution.
            RuleKind::Typing => {}
        }
    }

    let mut languages: Vec<String> = langs.into_iter().collect();
    languages.sort();
    let languages = languages
        .into_iter()
        .map(|language| {
            let canonical_sink_families_applicable = canonical_sink_audit_applies(&language);
            let sinks = CANONICAL_SINK_FAMILIES
                .iter()
                .map(|family| {
                    let (enabled, disabled) = sink_counts
                        .get(&(language.clone(), (*family).to_string()))
                        .copied()
                        .unwrap_or((0, 0));
                    (
                        (*family).to_string(),
                        PackAuditFamilyCount {
                            enabled,
                            disabled,
                            not_applicable: FAMILY_NOT_APPLICABLE.contains(&(language.as_str(), *family)),
                        },
                    )
                })
                .collect();
            let (source_enabled, source_disabled) = source_counts.get(&language).copied().unwrap_or((0, 0));
            let (sanitizer_enabled, sanitizer_disabled) =
                sanitizer_counts.get(&language).copied().unwrap_or((0, 0));
            let security_model = security_model_for_lang(&language).to_string();
            PackAuditLanguage {
                language,
                security_model,
                canonical_sink_families_applicable,
                sinks,
                sources: PackAuditCount {
                    enabled: source_enabled,
                    disabled: source_disabled,
                },
                sanitizers: PackAuditCount {
                    enabled: sanitizer_enabled,
                    disabled: sanitizer_disabled,
                },
            }
        })
        .collect();
    PackAuditReport { languages }
}

pub fn pack_tree(pack: &Rulepack, options: PackInventoryOptions) -> PackTreeReport {
    let rules = select_pack_rules(pack, &options);
    pack_tree_for_rules(pack, &rules)
}

pub fn pack_tree_for_rules(pack: &Rulepack, rules: &[&Rule]) -> PackTreeReport {
    let mut grouped: AHashMap<String, AHashMap<&'static str, AHashMap<String, Vec<&Rule>>>> = AHashMap::new();
    for rule in rules {
        grouped
            .entry(rule.language.clone())
            .or_default()
            .entry(rule_kind_str(rule.kind))
            .or_default()
            .entry(tree_file_rel(pack, rule))
            .or_default()
            .push(*rule);
    }

    let mut languages: Vec<String> = grouped.keys().cloned().collect();
    languages.sort();
    let languages = languages
        .into_iter()
        .map(|language| {
            let mut kinds = BTreeMap::new();
            if let Some(grouped_kinds) = grouped.get(&language) {
                for kind in ["source", "sink", "sanitizer"] {
                    let Some(files) = grouped_kinds.get(kind) else {
                        continue;
                    };
                    let mut file_names: Vec<String> = files.keys().cloned().collect();
                    file_names.sort();
                    let file_rows = file_names
                        .into_iter()
                        .map(|file_name| {
                            let mut rules = files[&file_name].clone();
                            rules.sort_by(|a, b| a.id.cmp(&b.id));
                            PackTreeFile {
                                file: tree_file_path(pack, &language, kind, &file_name),
                                rules: rules
                                    .into_iter()
                                    .map(|rule| PackTreeRule {
                                        id: rule.id.clone(),
                                        severity: rule.severity.map(|s| s.as_str().to_string()),
                                        enabled: rule.enabled,
                                        tag: rule.tag.clone(),
                                    })
                                    .collect(),
                            }
                        })
                        .collect();
                    kinds.insert(kind.to_string(), file_rows);
                }
            }
            PackTreeLanguage { language, kinds }
        })
        .collect();
    PackTreeReport { languages }
}

/// Run a per-file match phase: emit `PhaseStarted { label, total_files }`,
/// tick once per file, then `PhaseFinished`. Used internally by
/// `run_taint_analysis_with_phase_progress` so each matching pass shows
/// up as one progress bar with a known length.
fn gather_matches_phased<F>(
    ws: &Workspace,
    rules: &[&Rule],
    label: &'static str,
    scan_files: &[FileId],
    total_files: u64,
    factory: &Arc<crate::matcher::FactoryReturns>,
    on_progress: &mut F,
) -> Vec<RuleMatch>
where
    F: FnMut(AnalysisProgress),
{
    on_progress(AnalysisProgress::PhaseStarted {
        label,
        total: total_files,
    });
    let matches = match_rules_against_facts_with_progress_on_files(ws, rules, scan_files, factory, || {
        on_progress(AnalysisProgress::PhaseTicked);
    });
    on_progress(AnalysisProgress::PhaseFinished);
    matches
}

fn gather_taint_support_matches_phased<F>(
    ws: &Workspace,
    rules: &[&Rule],
    label: &'static str,
    scan_files: &[FileId],
    total_files: u64,
    factory: &Arc<crate::matcher::FactoryReturns>,
    on_progress: &mut F,
) -> Vec<RuleMatch>
where
    F: FnMut(AnalysisProgress),
{
    on_progress(AnalysisProgress::PhaseStarted {
        label,
        total: total_files,
    });
    let matches = match_rules_against_facts_for_taint_support_with_progress_on_files(
        ws,
        rules,
        scan_files,
        factory,
        || {
            on_progress(AnalysisProgress::PhaseTicked);
        },
    );
    on_progress(AnalysisProgress::PhaseFinished);
    matches
}

fn gather_inventory_matches_phased<F>(
    ws: &Workspace,
    rules: &[&Rule],
    label: &'static str,
    scan_files: &[FileId],
    total_files: u64,
    factory: &Arc<crate::matcher::FactoryReturns>,
    on_progress: &mut F,
) -> Vec<RuleMatch>
where
    F: FnMut(AnalysisProgress),
{
    on_progress(AnalysisProgress::PhaseStarted {
        label,
        total: total_files,
    });
    let matches = match_rules_against_facts_for_inventory_with_progress_on_files(
        ws,
        rules,
        scan_files,
        factory,
        || {
            on_progress(AnalysisProgress::PhaseTicked);
        },
    );
    on_progress(AnalysisProgress::PhaseFinished);
    matches
}

pub fn source_rule_matches_filters(
    rule: &Rule,
    trust: Option<&str>,
    category: Option<&str>,
    tag: Option<&str>,
) -> bool {
    trust.is_none_or(|t| rule.trust.is_some_and(|rt| rt.as_str() == t))
        && category.is_none_or(|c| rule.category.as_deref() == Some(c))
        && tag.is_none_or(|t| rule.tag.as_deref() == Some(t))
}

fn filter_source_hits_by_metadata(
    hits: &mut Vec<RuleMatch>,
    pack: &Rulepack,
    trust: Option<&str>,
    category: Option<&str>,
    tag: Option<&str>,
) {
    if trust.is_none() && category.is_none() && tag.is_none() {
        return;
    }
    hits.retain(|hit| source_hit_matches_metadata(hit, pack, trust, category, tag));
}

/// `(file, enclosing_fn)` → the set of base identifiers a concrete
/// (non-inferred) rulepack source match is rooted at in that function.
/// Used to drop redundant inferred entry-point param sources that only
/// re-describe a flow a precise source already covers.
fn concrete_source_param_bases(
    pack: &Rulepack,
    hits: &[RuleMatch],
) -> AHashMap<(String, String), AHashSet<String>> {
    let mut out: AHashMap<(String, String), AHashSet<String>> = AHashMap::default();
    for hit in hits {
        if hit.origin != MatchOrigin::Rulepack {
            continue;
        }
        // A sink-restricted concrete source is precise only for those sink
        // classes. It cannot subsume the broad inferred parameter for every
        // other class: a `payload` source restricted to deserialization must
        // not erase a real `payload -> Mongo.find` flow during source
        // discovery. Keep both here; finding-time compatibility and grouping
        // retain the concrete source wherever it is actually applicable.
        if pack.find_rule_by_id(&hit.rule_id).is_some_and(|rule| {
            rule.constraints
                .iter()
                .any(|constraint| matches!(constraint, ConstraintKind::SinkTagIn { .. }))
        }) {
            continue;
        }
        let Some(fn_name) = hit.enclosing_fn.clone() else {
            continue;
        };
        if let Some(base) = source_expr_base_identifier(&hit.match_text) {
            out.entry((hit.file.clone(), fn_name))
                .or_default()
                .insert(base.to_string());
        }
    }
    out
}

/// True when `inferred` is a synthetic entry-point param source whose
/// parameter is the root of a concrete source match in the same
/// function (so the concrete match is the precise evidence and the
/// inferred param is redundant).
fn inferred_param_subsumed_by_concrete(
    inferred: &RuleMatch,
    concrete: &AHashMap<(String, String), AHashSet<String>>,
) -> bool {
    if !matches!(
        inferred.origin,
        MatchOrigin::InferredUnreferencedParameter | MatchOrigin::InferredFrameworkParameter
    ) {
        return false;
    }
    let Some(fn_name) = inferred.enclosing_fn.as_ref() else {
        return false;
    };
    let param = inferred.match_text.trim();
    !param.is_empty()
        && concrete
            .get(&(inferred.file.clone(), fn_name.clone()))
            .is_some_and(|bases| bases.contains(param))
}

/// Leading identifier of a source expression — `r.URL.Query().Get` → `r`,
/// `payload[0]` → `payload`. Returns `None` when the text does not begin
/// with an identifier character.
fn source_expr_base_identifier(text: &str) -> Option<&str> {
    let trimmed = text.trim();
    let end = trimmed
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$' || c == '@'))
        .unwrap_or(trimmed.len());
    let base = &trimmed[..end];
    (!base.is_empty()).then_some(base)
}

fn source_hit_matches_metadata(
    hit: &RuleMatch,
    pack: &Rulepack,
    trust: Option<&str>,
    category: Option<&str>,
    tag: Option<&str>,
) -> bool {
    if hit.origin != MatchOrigin::Rulepack {
        return trust.is_none_or(|t| t == "local")
            && category.is_none_or(|c| c == "inferred")
            && tag.is_none_or(|t| t == "entry-point");
    }
    pack.find_rule_by_id(&hit.rule_id)
        .is_some_and(|rule| source_rule_matches_filters(rule, trust, category, tag))
}

fn source_finding_match(hit: &RuleMatch, pack: &Rulepack) -> Option<FindingMatch> {
    if hit.origin != MatchOrigin::Rulepack {
        Some(FindingMatch::from_inferred(hit))
    } else {
        pack.find_rule_by_id(&hit.rule_id)
            .map(|rule| FindingMatch::from_rule_match(hit, rule))
    }
}

fn func_id_for_match(ws: &Workspace, hit: &RuleMatch) -> Option<FuncId> {
    let expected_name = hit.enclosing_fn.as_deref();
    let global = ws.compiler_linkage_index();
    if let Some(entry) = ws
        .enclosing_index()
        .enclosing_for(global.as_ref(), hit.span.file, hit.span.start)
    {
        if expected_name.is_none_or(|name| name == entry.name) {
            return Some(FuncId::new(entry.symbol.raw()));
        }
    }

    let name = expected_name?;
    let decls = global.decls_in(hit.span.file);
    let mut best_containing: Option<(u64, FuncId)> = None;
    let mut unique_named: Option<FuncId> = None;
    let mut named_count = 0usize;

    for decl in decls {
        if decl.name != name {
            continue;
        }
        named_count = named_count.saturating_add(1);
        let fid = FuncId::new(decl.symbol.raw());
        unique_named = Some(fid);

        let body_span = decl.body_span.unwrap_or(decl.span);
        if span_contains(body_span, hit.span) || span_contains(decl.span, hit.span) {
            let width = decl.span.end.saturating_sub(decl.span.start);
            if best_containing.is_none_or(|(best_width, _)| width < best_width) {
                best_containing = Some((width, fid));
            }
        }
    }

    best_containing
        .map(|(_, fid)| fid)
        .or_else(|| (named_count == 1).then_some(unique_named?))
}

struct SourceLineageEmission<'a> {
    records: Vec<&'a TaintedCallEdge>,
    truncated_hops: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SourceLineageEnumeration {
    emitted_paths: usize,
    omitted_paths: usize,
    truncated_paths: usize,
    max_hops: usize,
    max_paths: usize,
}

fn collect_tainted_source_lineages<'a>(
    records: &'a [TaintedCallEdge],
    source: FuncId,
    max_extra: usize,
    max_paths: usize,
) -> (Vec<SourceLineageEmission<'a>>, SourceLineageEnumeration) {
    let mut stats = SourceLineageEnumeration {
        max_hops: max_extra,
        max_paths,
        ..Default::default()
    };
    if max_extra == 0 || max_paths == 0 || !records.iter().any(|record| record.trace_id != 0) {
        return (Vec::new(), stats);
    }
    let child_trace_ids: AHashSet<u64> = records
        .iter()
        .filter_map(|record| record.parent_trace_id)
        .collect();
    let mut by_id: AHashMap<u64, &TaintedCallEdge> = AHashMap::new();
    for record in records {
        if record.trace_id != 0 {
            by_id.entry(record.trace_id).or_insert(record);
        }
    }
    let mut endpoints: Vec<&TaintedCallEdge> = records
        .iter()
        .filter(|record| record.trace_id != 0)
        .filter(|record| !child_trace_ids.contains(&record.trace_id))
        .collect();
    endpoints.sort_by_key(|record| {
        (
            record.call_span.file.raw(),
            record.call_span.start,
            record.call_span.end,
            record.trace_id,
        )
    });

    let mut out = Vec::new();
    let mut seen: AHashSet<Vec<u64>> = AHashSet::new();
    for endpoint in endpoints {
        let Some(mut lineage) = lineage_records_for_trace_id_indexed(&by_id, endpoint.trace_id) else {
            continue;
        };
        if lineage.first().is_none_or(|record| record.caller != source) {
            continue;
        }
        let truncated_hops = lineage.len() > max_extra;
        if lineage.len() > max_extra {
            lineage.truncate(max_extra);
        }
        let key: Vec<u64> = lineage.iter().map(|record| record.trace_id).collect();
        if !key.is_empty() && seen.insert(key) {
            if out.len() < max_paths {
                if truncated_hops {
                    stats.truncated_paths += 1;
                }
                out.push(SourceLineageEmission {
                    records: lineage,
                    truncated_hops,
                });
                stats.emitted_paths += 1;
            } else {
                stats.omitted_paths += 1;
            }
        }
    }
    (out, stats)
}

fn chain_precision_for_records(records: &[&TaintedCallEdge]) -> Precision {
    records.iter().fold(Precision::Exact, |precision, record| {
        precision.meet(record.precision)
    })
}

#[derive(Clone, Debug)]
struct UnresolvedWorkspaceCallSite {
    span: Span,
    name: String,
}

struct GraphUnresolvedCallIndex {
    by_caller: AHashMap<FuncId, Vec<UnresolvedWorkspaceCallSite>>,
}

impl GraphUnresolvedCallIndex {
    fn new(call_graph: &bonsai_callgraph::ResolvedCallGraph, graph: &EntryTaintGraph) -> Self {
        let unresolved_sites: AHashSet<(FuncId, Span)> =
            call_graph.unresolved_workspace_call_sites().collect();
        let mut seen_sites: AHashSet<(FuncId, Span)> = AHashSet::new();
        let mut by_caller: AHashMap<FuncId, Vec<UnresolvedWorkspaceCallSite>> = AHashMap::new();
        for call in &graph.tainted_calls {
            if !matches!(call.kind, bonsai_taint::TaintedCallKind::Call)
                || !unresolved_sites.contains(&(call.caller, call.call_span))
                || !seen_sites.insert((call.caller, call.call_span))
            {
                continue;
            }
            by_caller
                .entry(call.caller)
                .or_default()
                .push(UnresolvedWorkspaceCallSite {
                    span: call.call_span,
                    name: call.name.clone(),
                });
        }
        for sites in by_caller.values_mut() {
            sites.sort_by(|a, b| {
                (a.span.start, a.span.end, a.name.as_str()).cmp(&(b.span.start, b.span.end, b.name.as_str()))
            });
            sites.dedup_by(|a, b| a.span == b.span && a.name == b.name);
        }
        Self { by_caller }
    }

    fn reasons_for_terminal_call(&self, terminal_call: &TaintedCall) -> Vec<String> {
        let Some(sites) = self.by_caller.get(&terminal_call.caller) else {
            return Vec::new();
        };
        let mut reasons = Vec::new();
        for site in sites {
            if site.span == terminal_call.call_span && site.name == terminal_call.name {
                continue;
            }
            if unresolved_call_site_is_in_terminal_expression(terminal_call.call_span, site.span) {
                reasons.push(format!("unresolved-call:{}", site.name));
            }
        }
        reasons.sort();
        reasons.dedup();
        reasons
    }
}

fn unresolved_call_site_is_in_terminal_expression(terminal_span: Span, unresolved_span: Span) -> bool {
    span_contains(terminal_span, unresolved_span)
}

struct CallEvidence {
    chain_funcs: Vec<FuncId>,
    sanitizer_candidate_funcs: Vec<FuncId>,
    chain_names: Vec<String>,
    chain_precision: Precision,
    taint_path: Vec<TaintPropagationStep>,
    sink_tainted_args: Vec<TaintedArgInfo>,
}

fn build_call_evidence<'a>(
    ws: &Workspace,
    trace_index: &AHashMap<u64, &'a TaintedCallEdge>,
    canonical_chain_index: &CanonicalChainIndex<'a>,
    source_func: FuncId,
    call: &TaintedCall,
) -> Option<CallEvidence> {
    let original_records = lineage_records_for_call_indexed(trace_index, call).unwrap_or_default();
    let (chain_funcs, sanitizer_candidate_funcs, chain_precision, taint_path) =
        if let Some(primary) = chain_funcs_for_lineage(&original_records, source_func, call.caller) {
            let mut records = original_records;
            let sanitizer_candidate_funcs =
                sanitizer_candidate_funcs_for_lineage(&records, source_func, call.caller);
            // Chain-quality upgrade: when the lineage walk anchored on
            // `parent_trace_id` goes through synthetic edges (Phase 3c field-flow
            // stitches, Phase 3d receiver-method propagation, or Return back-edges),
            // prefer an equivalent canonical call sequence with fewer synthetic hops.
            let mut chain_funcs = rewrite_chain_with_canonical_path(
                primary.clone(),
                canonical_chain_index,
                source_func,
                call.caller,
            );
            // The chain and the taint_path must describe the SAME route: rebuild
            // the step records along the rewritten chain from the recorded edges
            // it was found through. If any hop lacks a recorded edge, the rewrite
            // cannot be evidenced — keep the original lineage route instead.
            if chain_funcs != primary {
                match canonical_chain_index.records_along_chain(&chain_funcs) {
                    Some(rewritten) => records = rewritten,
                    None => chain_funcs = primary,
                }
            }
            let chain_precision = chain_precision_for_records(&records);
            let taint_path = taint_path_for_lineage(ws, &records, Some(call));
            (
                chain_funcs,
                sanitizer_candidate_funcs,
                chain_precision,
                taint_path,
            )
        } else {
            // A resolved callgraph route proves control connectivity, not the
            // route taken by this tainted value. Substituting an arbitrary
            // semantic path here can credit a sanitizer on a different route
            // and suppress a real finding. IDG propagation must supply the
            // concrete lineage (same-function flows are handled above by the
            // empty-record lineage case); otherwise no public finding is
            // emitted.
            return None;
        };
    if !chain_precision.is_semantic() {
        return None;
    }
    let chain_names = chain_names_for_path(ws, &chain_funcs)?;
    let sink_decl = ws.exact_decl(SymbolId::new(call.caller.raw()));
    let sink_events = sink_decl.as_deref().map(|decl| decl.flow_events.as_slice());
    let mut sink_tainted_args: Vec<TaintedArgInfo> = call
        .tainted_args
        .iter()
        .map(|arg| {
            sink_events.map_or_else(
                || TaintedArgInfo {
                    index: arg.index,
                    value_text: arg.value_text.clone(),
                    ..TaintedArgInfo::default()
                },
                |events| tainted_arg_info_from_events(events, call.call_span, arg),
            )
        })
        .collect();
    if let Some(receiver) = call.tainted_receiver.as_deref() {
        sink_tainted_args.push(TaintedArgInfo {
            index: usize::MAX,
            value_text: receiver.to_string(),
            place: Some(receiver.to_string()),
            source_names: Vec::new(),
        });
    }
    Some(CallEvidence {
        chain_funcs,
        sanitizer_candidate_funcs,
        chain_names,
        chain_precision,
        taint_path,
        sink_tainted_args,
    })
}

fn sanitizer_candidate_funcs_for_lineage(
    records: &[&TaintedCallEdge],
    source_func: FuncId,
    terminal_func: FuncId,
) -> Vec<FuncId> {
    let mut funcs = Vec::with_capacity(records.len().saturating_mul(2).saturating_add(2));
    push_unique_func(&mut funcs, source_func);
    for record in records {
        push_unique_func(&mut funcs, record.caller);
        push_unique_func(&mut funcs, record.callee);
    }
    push_unique_func(&mut funcs, terminal_func);
    funcs
}

fn push_unique_func(funcs: &mut Vec<FuncId>, func: FuncId) {
    if !funcs.contains(&func) {
        funcs.push(func);
    }
}

#[cfg(test)]
fn lineage_records_for_call<'a>(
    records: &'a [TaintedCallEdge],
    terminal_call: &TaintedCall,
) -> Option<Vec<&'a TaintedCallEdge>> {
    let by_id = trace_record_index(records);
    lineage_records_for_call_indexed(&by_id, terminal_call)
}

fn trace_record_index(records: &[TaintedCallEdge]) -> AHashMap<u64, &TaintedCallEdge> {
    let mut by_id: AHashMap<u64, &TaintedCallEdge> = AHashMap::new();
    for record in records {
        if record.trace_id != 0 {
            by_id.entry(record.trace_id).or_insert(record);
        }
    }
    by_id
}

fn lineage_records_for_call_indexed<'a>(
    by_id: &AHashMap<u64, &'a TaintedCallEdge>,
    terminal_call: &TaintedCall,
) -> Option<Vec<&'a TaintedCallEdge>> {
    match terminal_call.parent_trace_id {
        Some(trace_id) => lineage_records_for_trace_id_indexed(by_id, trace_id),
        None => Some(Vec::new()),
    }
}

fn lineage_records_for_trace_id_indexed<'a>(
    by_id: &AHashMap<u64, &'a TaintedCallEdge>,
    trace_id: u64,
) -> Option<Vec<&'a TaintedCallEdge>> {
    let mut current = Some(trace_id);
    let mut lineage = Vec::new();
    let mut seen = AHashSet::new();
    while let Some(trace_id) = current {
        if !seen.insert(trace_id) {
            return None;
        }
        let record = *by_id.get(&trace_id)?;
        lineage.push(record);
        current = record.parent_trace_id;
    }
    lineage.reverse();
    Some(lineage)
}

/// Replace the lineage-walk chain with a path that minimises the
/// number of synthetic-edge hops (Phase 3c field-flow stitches,
/// Phase 3d receiver-method propagation, Return back-edges — all
/// sentinel `arg_idx == usize::MAX`). Only fires when the alternative
/// strictly reduces synthetic-edge count. Otherwise the original chain is
/// returned.
struct CanonicalChainIndex<'a> {
    adjacency: AHashMap<FuncId, Vec<(FuncId, bool)>>,
    edge_has_any: AHashSet<(FuncId, FuncId)>,
    edge_has_real: AHashSet<(FuncId, FuncId)>,
    /// Representative record per edge — a real (non-synthetic) one when
    /// any exists. Lets a canonically rewritten chain rebuild its
    /// taint_path from the actual recorded propagation on each hop.
    edge_record: AHashMap<(FuncId, FuncId), &'a TaintedCallEdge>,
    /// One exact shortest-path tree per semantic source. A source graph can
    /// contain many terminal sink functions; running Dijkstra separately for
    /// every terminal repeats the same graph search. The tree is complete and
    /// uncapped, and each terminal path is reconstructed in O(path length).
    best_chain_trees: std::cell::RefCell<AHashMap<FuncId, CanonicalBestTree>>,
}

struct CanonicalBestTree {
    best: AHashMap<FuncId, (u32, u32)>,
    predecessor: AHashMap<FuncId, FuncId>,
}

impl<'a> CanonicalChainIndex<'a> {
    fn new(records: &'a [TaintedCallEdge], call_graph: &'a bonsai_callgraph::ResolvedCallGraph) -> Self {
        let mut edge_synthetic: AHashMap<(FuncId, FuncId), bool> = AHashMap::default();
        let mut edge_has_any = AHashSet::default();
        let mut edge_has_real = AHashSet::default();
        let mut edge_record: AHashMap<(FuncId, FuncId), &'a TaintedCallEdge> = AHashMap::default();
        let mut callgraph_edge_cache: AHashMap<(FuncId, FuncId), bool> = AHashMap::default();
        for record in records {
            let edge = (record.caller, record.callee);
            let has_semantic_call_edge = *callgraph_edge_cache
                .entry(edge)
                .or_insert_with(|| semantic_callgraph_has_edge(call_graph, record.caller, record.callee));
            let is_synthetic = edge_is_synthetic(record, has_semantic_call_edge);
            edge_has_any.insert(edge);
            if !is_synthetic {
                // First real record wins (record order is deterministic);
                // a real record always replaces a synthetic placeholder.
                if !edge_has_real.contains(&edge) {
                    edge_record.insert(edge, record);
                }
                edge_has_real.insert(edge);
            } else {
                edge_record.entry(edge).or_insert(record);
            }
            edge_synthetic
                .entry(edge)
                .and_modify(|existing| *existing &= is_synthetic)
                .or_insert(is_synthetic);
        }
        let mut adjacency: AHashMap<FuncId, Vec<(FuncId, bool)>> = AHashMap::default();
        for ((caller, callee), is_synthetic) in edge_synthetic {
            adjacency.entry(caller).or_default().push((callee, is_synthetic));
        }
        for neighbors in adjacency.values_mut() {
            neighbors.sort_by_key(|(callee, is_synthetic)| (callee.raw(), *is_synthetic));
        }
        Self {
            adjacency,
            edge_has_any,
            edge_has_real,
            edge_record,
            best_chain_trees: std::cell::RefCell::new(AHashMap::default()),
        }
    }

    /// Recorded propagation edges along `chain`, one per adjacent pair.
    /// `None` when any hop has no recorded edge — the chain then cannot
    /// be evidenced step-by-step and callers must keep the original
    /// lineage instead.
    fn records_along_chain(&self, chain: &[FuncId]) -> Option<Vec<&'a TaintedCallEdge>> {
        if chain.len() < 2 {
            return None;
        }
        chain
            .windows(2)
            .map(|pair| self.edge_record.get(&(pair[0], pair[1])).copied())
            .collect()
    }

    fn best_chain(&self, source_func: FuncId, terminal_func: FuncId) -> Option<Vec<FuncId>> {
        if !self.best_chain_trees.borrow().contains_key(&source_func) {
            let tree = canonical_best_tree(self, source_func);
            self.best_chain_trees.borrow_mut().insert(source_func, tree);
        }
        let trees = self.best_chain_trees.borrow();
        canonical_chain_from_tree(trees.get(&source_func)?, source_func, terminal_func)
    }
}

fn semantic_callgraph_has_edge(
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    caller: FuncId,
    callee: FuncId,
) -> bool {
    call_graph
        .callees_of(caller)
        .any(|edge| edge.to == callee && edge.precision.is_semantic())
}

fn rewrite_chain_with_canonical_path(
    primary: Vec<FuncId>,
    index: &CanonicalChainIndex<'_>,
    source_func: FuncId,
    terminal_func: FuncId,
) -> Vec<FuncId> {
    let primary_synth = chain_synth_count(&primary, index);
    if primary_synth == 0 {
        return primary;
    }
    let Some(alt) = index.best_chain(source_func, terminal_func) else {
        return primary;
    };
    let alt_synth = chain_synth_count(&alt, index);
    // A shorter resolved path is valid evidence, not a loss of coverage.
    // Rewrite only when it strictly removes synthetic hops; ties retain the
    // trace-derived primary chain for stable presentation.
    if alt_synth < primary_synth {
        alt
    } else {
        primary
    }
}

fn edge_is_synthetic(record: &TaintedCallEdge, has_semantic_call_edge: bool) -> bool {
    if has_semantic_call_edge {
        return false;
    }
    if record.tainted_args.is_empty() {
        return true;
    }
    record.tainted_args.iter().all(|arg| arg.index == usize::MAX)
}

#[cfg(test)]
mod positional_index_regression_tests {
    use super::*;

    fn edge_with_arg(index: usize) -> TaintedCallEdge {
        TaintedCallEdge {
            trace_id: 1,
            parent_trace_id: None,
            caller: FuncId::new(1),
            callee: FuncId::new(2),
            call_span: Span::new(FileId::new(0), 10, 20),
            tainted_args: vec![bonsai_taint::TaintedArg {
                index,
                value_text: format!("arg{index}"),
                param_name: format!("param{index}"),
            }],
            precision: Precision::Exact,
            edge_kind: bonsai_callgraph::EdgeKind::Direct,
        }
    }

    #[test]
    fn positional_255_is_not_a_synthetic_edge() {
        assert!(!edge_is_synthetic(&edge_with_arg(255), false));
        assert!(edge_is_synthetic(&edge_with_arg(usize::MAX), false));
    }
}

fn chain_synth_count(chain: &[FuncId], index: &CanonicalChainIndex<'_>) -> usize {
    let mut count = 0;
    for window in chain.windows(2) {
        let (a, b) = (window[0], window[1]);
        let found_any = index.edge_has_any.contains(&(a, b));
        let found_real = index.edge_has_real.contains(&(a, b));
        if found_any && !found_real {
            count += 1;
        }
    }
    count
}

/// Search `all_records` for a path from `source_func` to
/// `terminal_func` with the fewest synthetic hops, then the fewest total
/// hops. The finite graph and best-cost table terminate cycles without a
/// fixed depth limit or path-vector cloning.
#[cfg(test)]
fn best_chain_through_real_edges(
    index: &CanonicalChainIndex<'_>,
    source_func: FuncId,
    terminal_func: FuncId,
) -> Option<Vec<FuncId>> {
    let tree = canonical_best_tree(index, source_func);
    canonical_chain_from_tree(&tree, source_func, terminal_func)
}

fn canonical_best_tree(index: &CanonicalChainIndex<'_>, source_func: FuncId) -> CanonicalBestTree {
    use std::collections::BinaryHeap;
    let mut heap: BinaryHeap<std::cmp::Reverse<(u32, u32, FuncId)>> = BinaryHeap::new();
    let mut best: AHashMap<FuncId, (u32, u32)> = AHashMap::with_capacity(index.adjacency.len());
    let mut predecessor: AHashMap<FuncId, FuncId> = AHashMap::with_capacity(index.adjacency.len());
    heap.push(std::cmp::Reverse((0, 0, source_func)));
    best.insert(source_func, (0, 0));
    while let Some(std::cmp::Reverse((synthetic_hops, hops, current))) = heap.pop() {
        if best.get(&current).copied() != Some((synthetic_hops, hops)) {
            continue;
        }
        let Some(neighbors) = index.adjacency.get(&current) else {
            continue;
        };
        for &(next_f, is_synth) in neighbors {
            let next_cost = (
                synthetic_hops.saturating_add(u32::from(is_synth)),
                hops.saturating_add(1),
            );
            if best.get(&next_f).is_some_and(|existing| *existing <= next_cost) {
                continue;
            }
            best.insert(next_f, next_cost);
            predecessor.insert(next_f, current);
            heap.push(std::cmp::Reverse((next_cost.0, next_cost.1, next_f)));
        }
    }
    CanonicalBestTree { best, predecessor }
}

fn canonical_chain_from_tree(
    tree: &CanonicalBestTree,
    source_func: FuncId,
    terminal_func: FuncId,
) -> Option<Vec<FuncId>> {
    tree.best.get(&terminal_func)?;
    let mut current = terminal_func;
    let mut path = vec![current];
    while current != source_func {
        current = *tree.predecessor.get(&current)?;
        path.push(current);
    }
    path.reverse();
    Some(path)
}

fn chain_funcs_for_lineage(
    records: &[&TaintedCallEdge],
    source_func: FuncId,
    terminal_func: FuncId,
) -> Option<Vec<FuncId>> {
    if records.is_empty() {
        return (source_func == terminal_func).then_some(vec![source_func]);
    }
    let mut funcs = Vec::with_capacity(records.len() + 1);
    let first = records.first()?;
    if first.caller != source_func {
        return None;
    }
    funcs.push(first.caller);
    for record in records {
        if funcs.last().copied() != Some(record.caller) {
            return None;
        }
        funcs.push(record.callee);
    }
    if funcs.last().copied() != Some(terminal_func) {
        return None;
    }
    // Synthetic `Return → CallRet` stitches revisit the owning caller in the
    // raw trace (`handle → transform → handle → sink`). Rendering the caller
    // twice is noise, but removing every function between the two visits also
    // erases the helper that actually transformed the value. Preserve each
    // evidenced function at its first occurrence and omit only revisits. The
    // raw record chain above remains fully validated and the taint-path steps
    // still retain the return stitch; this is display compaction, not a graph
    // search or a semantic cap.
    let mut seen: AHashSet<FuncId> = AHashSet::with_capacity(funcs.len());
    let mut deduped: Vec<FuncId> = Vec::with_capacity(funcs.len());
    for f in funcs.iter().copied() {
        if !seen.insert(f) {
            continue;
        }
        deduped.push(f);
    }
    Some(deduped)
}

fn propagation_step_for_edge(
    ws: &Workspace,
    record: &TaintedCallEdge,
    names: &AHashMap<FuncId, String>,
) -> Option<TaintPropagationStep> {
    if record.caller == record.callee {
        return None;
    }
    let (file, line, column) = resolve_span_location(ws, record.call_span);
    let caller = path_display_name(ws, names, record.caller);
    let callee = path_display_name(ws, names, record.callee);
    TaintPropagationStep {
        caller,
        callee,
        file,
        line,
        column,
        tainted_args: record
            .tainted_args
            .iter()
            .map(|arg| TaintPropagationArg {
                index: arg.index,
                value_text: arg.value_text.clone(),
                param_name: arg.param_name.clone(),
            })
            .collect(),
    }
    .into()
}

fn propagation_step_for_terminal_call(
    ws: &Workspace,
    call: &TaintedCall,
    names: &AHashMap<FuncId, String>,
) -> TaintPropagationStep {
    let (file, line, column) = resolve_span_location(ws, call.call_span);
    let mut tainted_args: Vec<TaintPropagationArg> = call
        .tainted_args
        .iter()
        .map(|arg| TaintPropagationArg {
            index: arg.index,
            value_text: arg.value_text.clone(),
            param_name: String::new(),
        })
        .collect();
    if let Some(receiver) = call.tainted_receiver.as_deref() {
        tainted_args.push(TaintPropagationArg {
            index: usize::MAX,
            value_text: receiver.to_string(),
            param_name: receiver.to_string(),
        });
    }
    let caller = path_display_name(ws, names, call.caller);
    TaintPropagationStep {
        caller: if caller == call.name {
            func_display_name_with_site(ws, call.caller)
        } else {
            caller
        },
        callee: call.name.clone(),
        file,
        line,
        column,
        tainted_args,
    }
}

fn taint_path_for_lineage(
    ws: &Workspace,
    records: &[&TaintedCallEdge],
    terminal_call: Option<&TaintedCall>,
) -> Vec<TaintPropagationStep> {
    let names = path_display_names(ws, records, terminal_call);
    let mut path: Vec<TaintPropagationStep> = records
        .iter()
        .filter_map(|record| propagation_step_for_edge(ws, record, &names))
        .collect();
    if let Some(call) = terminal_call {
        path.push(propagation_step_for_terminal_call(ws, call, &names));
    }
    normalize_taint_path(path)
}

/// Display names for every function on a taint path. A bare name that
/// covers more than one distinct function anywhere on the path is
/// qualified with `@file:line` on EVERY step — the same policy
/// `chain_names_for_path` applies to the chain — so adjacent steps'
/// callee/caller strings always join and the path agrees with
/// `chain_display`. Per-step qualification (the old behavior) rendered
/// the same function bare in one step and qualified in the next,
/// making connected chains look broken.
fn path_display_names(
    ws: &Workspace,
    records: &[&TaintedCallEdge],
    terminal_call: Option<&TaintedCall>,
) -> AHashMap<FuncId, String> {
    let mut funcs: Vec<FuncId> = Vec::with_capacity(records.len() * 2 + 1);
    for record in records {
        funcs.push(record.caller);
        funcs.push(record.callee);
    }
    if let Some(call) = terminal_call {
        funcs.push(call.caller);
    }
    funcs.sort_unstable();
    funcs.dedup();
    let mut by_name: BTreeMap<String, Vec<FuncId>> = BTreeMap::new();
    for func in &funcs {
        by_name
            .entry(func_display_name(ws, *func))
            .or_default()
            .push(*func);
    }
    let mut names = AHashMap::with_capacity(funcs.len());
    for (name, ids) in by_name {
        let ambiguous = ids.len() > 1;
        for func in ids {
            let display = if ambiguous {
                func_display_name_with_site(ws, func)
            } else {
                name.clone()
            };
            names.insert(func, display);
        }
    }
    names
}

fn path_display_name(ws: &Workspace, names: &AHashMap<FuncId, String>, func: FuncId) -> String {
    names
        .get(&func)
        .cloned()
        .unwrap_or_else(|| func_display_name(ws, func))
}

fn normalize_taint_path(path: Vec<TaintPropagationStep>) -> Vec<TaintPropagationStep> {
    let mut normalized: Vec<TaintPropagationStep> = Vec::with_capacity(path.len());
    for step in path {
        let Some(previous) = normalized.last_mut() else {
            normalized.push(step);
            continue;
        };
        if !same_taint_report_site(previous, &step) {
            normalized.push(step);
            continue;
        }
        merge_taint_report_step(previous, step);
    }
    normalized
}

fn align_terminal_taint_step_to_sink(
    mut path: Vec<TaintPropagationStep>,
    sink: &RuleMatch,
) -> Vec<TaintPropagationStep> {
    let Some(step) = path.last_mut() else {
        return path;
    };
    if !terminal_taint_step_should_align_to_sink(step, sink) {
        return path;
    }
    step.file.clone_from(&sink.file);
    step.line = sink.line;
    step.column = sink.column;
    if !sink.match_text.is_empty() {
        step.callee.clone_from(&sink.match_text);
    }
    normalize_taint_path(path)
}

fn terminal_taint_step_should_align_to_sink(step: &TaintPropagationStep, sink: &RuleMatch) -> bool {
    if step.file != sink.file || sink.line == 0 {
        return false;
    }
    if step.line == sink.line && (step.column == sink.column || sink.column == 0) {
        return false;
    }
    if !sink.enclosing_fn.as_deref().is_none_or(|enclosing| {
        let caller = display_callee_tail(&step.caller);
        caller == enclosing || step.caller == enclosing
    }) {
        return false;
    }
    step.line == 0
        || step.line < sink.line
        || (step.line == sink.line && (step.column == 0 || step.column < sink.column))
}

fn same_taint_report_site(left: &TaintPropagationStep, right: &TaintPropagationStep) -> bool {
    left.file == right.file && left.line == right.line && (left.line != 0 || left.column == right.column)
}

fn merge_taint_report_step(previous: &mut TaintPropagationStep, next: TaintPropagationStep) {
    if previous.caller.is_empty() {
        previous.caller = next.caller;
    }
    if !next.callee.is_empty() {
        previous.callee = next.callee;
    }
    if previous.column == 0 {
        previous.column = next.column;
    }
    for arg in next.tainted_args {
        if !previous.tainted_args.iter().any(|existing| {
            existing.index == arg.index
                && existing.value_text == arg.value_text
                && existing.param_name == arg.param_name
        }) {
            previous.tainted_args.push(arg);
        }
    }
}

fn func_display_name(ws: &Workspace, func: FuncId) -> String {
    ws.compiler_linkage_index()
        .decl_of(SymbolId::new(func.raw()))
        .map(|decl| decl.name.clone())
        .unwrap_or_else(|| format!("func#{}", func.raw()))
}

fn func_display_name_with_site(ws: &Workspace, func: FuncId) -> String {
    let global = ws.compiler_linkage_index();
    let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
        return format!("func#{}", func.raw());
    };

    let file_name = ws
        .vfs()
        .path(decl.span.file)
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
        .unwrap_or_default();
    let line = ws
        .vfs()
        .snapshot(decl.span.file)
        .ok()
        .map(|snapshot| {
            let span_map =
                bonsai_common::cached_span_map_arc(decl.span.file, snapshot.version, &snapshot.text);
            span_map.line_col(decl.name_span.start).line
        })
        .unwrap_or_default();

    if file_name.is_empty() || line == 0 {
        format!("{}#{}", decl.name, func.raw())
    } else {
        format!("{}@{}:{}", decl.name, file_name, line)
    }
}

fn resolve_span_location(ws: &Workspace, span: Span) -> (String, u32, u32) {
    let file = span.file;
    let path = ws
        .vfs()
        .path(file)
        .map(|file_path| file_path.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Ok(snapshot) = ws.vfs().snapshot(file) {
        let span_map = bonsai_common::cached_span_map_arc(file, snapshot.version, &snapshot.text);
        let line_col = span_map.line_col(span.start);
        return (path, line_col.line, line_col.column);
    }
    (path, 0, 0)
}

/// Apply CLI `--files` / `--exclude-files` filters in place. Empty
/// `files` means "no positive filter — keep everything"; empty
/// `exclude` means "no negative filter — drop nothing".
fn filter_by_path(ws: &Workspace, matches: &mut Vec<RuleMatch>, files: &[String], exclude: &[String]) {
    let root = ws.db().workspace_root();
    if !files.is_empty() {
        matches.retain(|rule_match| {
            files
                .iter()
                .any(|filter| path_filter_matches_with_root(root.as_deref(), &rule_match.file, filter))
        });
    }
    if !exclude.is_empty() {
        matches.retain(|rule_match| {
            !exclude
                .iter()
                .any(|filter| path_filter_matches_with_root(root.as_deref(), &rule_match.file, filter))
        });
    }
}

fn security_scan_files(
    ws: &Workspace,
    files: &[String],
    exclude_files: &[String],
    exclude_tests: bool,
) -> Vec<FileId> {
    let root = ws.db().workspace_root();
    ws.db()
        .vfs()
        .all_files()
        .into_iter()
        .filter(|&file| {
            let path = ws
                .vfs()
                .path(file)
                .ok()
                .map(|path| path.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            (files.is_empty()
                || files
                    .iter()
                    .any(|filter| path_filter_matches_with_root(root.as_deref(), &path, filter)))
                && !path_is_excluded_with_root(root.as_deref(), &path, exclude_files, exclude_tests)
        })
        .collect()
}

fn ensure_workspace_files_indexed(ws: &Workspace, files: &[FileId]) {
    use rayon::prelude::*;
    files.par_iter().for_each(|&file| {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    });
}

fn path_is_excluded_with_root(
    root: Option<&Path>,
    path: &str,
    exclude_files: &[String],
    exclude_tests: bool,
) -> bool {
    (exclude_tests && path_is_test_file_with_root(root, path))
        || exclude_files
            .iter()
            .any(|filter| path_filter_matches_with_root(root, path, filter))
}

fn path_is_test_file_with_root(root: Option<&Path>, path: &str) -> bool {
    let relative = workspace_relative_filter_path(root, path);
    if relative.starts_with('/') {
        return crate::finding::path_is_test_file(&relative);
    }
    crate::finding::path_is_test_file(&format!("/{relative}"))
}

fn taint_path_has_excluded_file(
    ws: &Workspace,
    taint_path: &[TaintPropagationStep],
    exclude_files: &[String],
    exclude_tests: bool,
) -> bool {
    let root = ws.db().workspace_root();
    taint_path
        .iter()
        .any(|step| path_is_excluded_with_root(root.as_deref(), &step.file, exclude_files, exclude_tests))
}

fn func_file_path(ws: &Workspace, func: FuncId) -> Option<String> {
    let global = ws.compiler_linkage_index();
    let decl = global.decl_of(SymbolId::new(func.raw()))?;
    ws.vfs()
        .path(decl.span.file)
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

fn source_candidate_has_excluded_path(
    ws: &Workspace,
    candidate: &SourceAnalysisCandidate,
    exclude_files: &[String],
    exclude_tests: bool,
) -> bool {
    let root = ws.db().workspace_root();
    path_is_excluded_with_root(
        root.as_deref(),
        &candidate.source.file,
        exclude_files,
        exclude_tests,
    ) || taint_path_has_excluded_file(ws, &candidate.taint_path, exclude_files, exclude_tests)
        || candidate.path.iter().any(|&func| {
            func_file_path(ws, func).as_deref().is_some_and(|path| {
                path_is_excluded_with_root(root.as_deref(), path, exclude_files, exclude_tests)
            })
        })
}

fn finding_has_excluded_path(
    ws: &Workspace,
    finding: &Finding,
    exclude_files: &[String],
    exclude_tests: bool,
) -> bool {
    let root = ws.db().workspace_root();
    path_is_excluded_with_root(
        root.as_deref(),
        &finding.source.file,
        exclude_files,
        exclude_tests,
    ) || path_is_excluded_with_root(root.as_deref(), &finding.sink.file, exclude_files, exclude_tests)
        || taint_path_has_excluded_file(ws, &finding.taint_path, exclude_files, exclude_tests)
        || finding.sanitizers_seen.iter().any(|sanitizer| {
            path_is_excluded_with_root(root.as_deref(), &sanitizer.file, exclude_files, exclude_tests)
        })
}

fn workspace_relative_filter_path(root: Option<&Path>, path: &str) -> String {
    let normalized_path = normalize_path_for_filter(path);
    let Some(root) = root else {
        return normalized_path;
    };
    if let Ok(relative) = Path::new(path).strip_prefix(root) {
        return normalize_path_for_filter(&relative.to_string_lossy());
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

fn path_filter_matches_with_root(root: Option<&Path>, path: &str, filter: &str) -> bool {
    let relative = workspace_relative_filter_path(root, path);
    if path_filter_matches(&relative, filter) {
        return true;
    }
    filter_looks_like_absolute_path(filter) && path_filter_matches(path, filter)
}

fn filter_looks_like_absolute_path(filter: &str) -> bool {
    let normalized = normalize_path_for_filter(filter);
    if normalized.len() >= 3 && normalized.as_bytes()[1] == b':' && normalized.as_bytes()[2] == b'/' {
        return true;
    }
    Path::new(filter).is_absolute() && normalized.trim_matches('/').contains('/')
}

/// True when `path` matches the CLI path filter `filter`.
/// Substring match for bare names; component-aware match for
/// filters containing `/`.
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

/// Path filter with `/` component awareness. `/foo/` matches `foo` as
/// a complete path component (start of path, end, or surrounded by
/// slashes); `foo/bar` matches anywhere as a substring.
fn path_filter_with_separator_matches(path: &str, filter: &str) -> bool {
    let trimmed = filter.trim_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    // Leading or trailing slash on the filter signals "match this as
    // a directory component", not as raw substring.
    let is_component_filter = filter.starts_with('/') || filter.ends_with('/');
    if is_component_filter {
        // Anchored comparison must strip the path's own leading slash the
        // same way the filter was trimmed, or an explicit absolute filter
        // (`/abs/ws/app.py`) can never equal the absolute path it names.
        let anchored = path.trim_start_matches('/');
        return anchored == trimmed
            || anchored.starts_with(&format!("{trimmed}/"))
            || path.contains(&format!("/{trimmed}/"));
    }
    path.contains(filter)
}

/// Normalise a path for filter comparison: forward slashes only, no
/// leading `./`. Lets Windows-emitted backslash paths and shell-glob
/// `./foo` prefixes match the same filter strings.
fn normalize_path_for_filter(value: &str) -> String {
    value.replace('\\', "/").trim_start_matches("./").to_string()
}

/// Stable matcher-output sort: language, file, line, column. Required for
/// deterministic finding ids and reproducible fixed-point scheduling.
fn sort_matches(matches: &mut [RuleMatch]) {
    matches.sort_by(|a, b| {
        (a.language.as_str(), a.file.as_str(), a.line, a.column).cmp(&(
            b.language.as_str(),
            b.file.as_str(),
            b.line,
            b.column,
        ))
    });
}

/// Drop matches whose surface site identity is identical to a
/// preceding entry. The matcher pipeline can emit the same call
/// site through more than one fact stream (for example, a real
/// nested receiver call plus a shortened call fact at the same
/// span). For inventory output, one rule at one concrete location
/// should render once; when duplicate streams disagree on text,
/// keep the longer text because it carries the most receiver context.
///
/// Only safe to call on inventory output — the taint-analysis
/// pipeline consumes the broader match stream where multiple
/// entries per call site carry distinct downstream context.
fn dedup_inventory_matches(matches: &mut Vec<RuleMatch>) {
    let mut seen: AHashMap<InventoryMatchIdentity, usize> = AHashMap::new();
    let mut deduped: Vec<RuleMatch> = Vec::with_capacity(matches.len());
    for m in matches.drain(..) {
        let key = (
            m.language.clone(),
            m.file.clone(),
            m.line,
            m.column,
            m.rule_id.clone(),
            m.enclosing_fn.clone(),
        );
        if let Some(&idx) = seen.get(&key) {
            if m.match_text.len() > deduped[idx].match_text.len() {
                deduped[idx] = m;
            }
            continue;
        }
        seen.insert(key, deduped.len());
        deduped.push(m);
    }
    *matches = deduped;
}

fn combine_source_analysis_candidates(
    flows: Vec<SourceAnalysisCandidate>,
) -> Vec<CombinedSourceAnalysisCandidate> {
    let mut groups: Vec<CombinedSourceAnalysisCandidate> = Vec::new();
    let mut index: AHashMap<String, usize> = AHashMap::new();
    for item in flows {
        let key = item.flow_id.clone();
        if let Some(&idx) = index.get(&key) {
            merge_source_lineage_status(&mut groups[idx].lineage, item.lineage);
            groups[idx].precision = groups[idx].precision.meet(item.precision);
            if !same_source_site(&groups[idx].source, &item.source)
                && !groups[idx]
                    .additional_sources
                    .iter()
                    .any(|source| same_source_site(source, &item.source))
            {
                groups[idx].additional_sources.push(item.source);
            }
            continue;
        }
        let idx = groups.len();
        index.insert(key, idx);
        groups.push(CombinedSourceAnalysisCandidate {
            source: item.source,
            chain_names: item.chain_names,
            path: item.path,
            flow_id: item.flow_id,
            taint_path: item.taint_path,
            precision: item.precision,
            lineage: item.lineage,
            additional_sources: Vec::new(),
        });
    }
    groups
}

fn merge_source_lineage_status(current: &mut SourceLineageStatus, incoming: SourceLineageStatus) {
    current.complete = current.complete && incoming.complete;
    current.truncated_hops = current.truncated_hops || incoming.truncated_hops;
    current.omitted_paths = current.omitted_paths.saturating_add(incoming.omitted_paths);
    current.emitted_paths = current.emitted_paths.saturating_add(incoming.emitted_paths);
    current.max_hops = current.max_hops.max(incoming.max_hops);
    current.max_paths = current.max_paths.max(incoming.max_paths);
}

fn chain_names_for_path(ws: &Workspace, path: &[FuncId]) -> Option<Vec<String>> {
    let global = ws.compiler_linkage_index();
    let named_funcs: Option<Vec<(FuncId, String)>> = path
        .iter()
        .map(|func| {
            global
                .decl_of(SymbolId::new(func.raw()))
                .map(|decl| (*func, decl.name.clone()))
        })
        .collect();
    let named_funcs = named_funcs?;
    // Qualify only when one bare name covers more than one DISTINCT
    // function — same policy as `path_display_names`, so the chain and
    // the taint path render every hop identically. A function repeated
    // in the chain (recursion) stays bare.
    let mut funcs_by_name: BTreeMap<String, BTreeSet<FuncId>> = BTreeMap::new();
    for (func, name) in &named_funcs {
        funcs_by_name.entry(name.clone()).or_default().insert(*func);
    }
    Some(
        named_funcs
            .into_iter()
            .map(|(func, name)| {
                if funcs_by_name
                    .get(&name)
                    .is_some_and(|distinct| distinct.len() > 1)
                {
                    func_display_name_with_site(ws, func)
                } else {
                    name
                }
            })
            .collect(),
    )
}

/// True when two source-side `FindingMatch`es refer to the exact
/// same call-site in the source code. Used during finding combination
/// to avoid pushing duplicate sources onto a group.
fn same_source_site(a: &FindingMatch, b: &FindingMatch) -> bool {
    a.rule_id == b.rule_id && a.file == b.file && a.line == b.line && a.column == b.column
}

fn finding_match_identity_token(m: &FindingMatch) -> String {
    format!("{}@{}:{}:{}", m.rule_id, m.file, m.line, m.column)
}

fn rule_match_identity_token(rule_id: &str, m: &RuleMatch) -> String {
    format!("{}@{}:{}:{}", rule_id, m.file, m.line, m.column)
}

/// Join a chain into a key of the hop names as rendered. `chain_names_for_path`
/// suffixes ambiguous names with `@file:line` so the rendered chain stays
/// unambiguous; strip the suffix here so equivalently-named chains share one
/// grouping key regardless of which concrete decl each hop resolved to.
fn displayed_chain_key(chain_names: &[String]) -> String {
    chain_names
        .iter()
        .map(|name| name.split('@').next().unwrap_or(name.as_str()))
        .collect::<Vec<_>>()
        .join("\0")
}

/// Drop inferred-source findings whose source-side field name
/// Identity of a finding's sink site — used to fold a dropped-but-
/// equivalent inferred finding into the concrete finding that covers
/// the same sink.
struct SinkSiteKey {
    language: String,
    file: String,
    line: u32,
    column: u32,
    rule_id: String,
}

/// doesn't match any of the sink's `tainted_args` — collapses
/// `entry-point.class_field.inherited` over-approximations (Java
/// 3→1, Python 5→4) while preserving inferred sources when they're
/// the only upstream (`unreferenced_entry.param_N` shapes).
fn drop_field_mismatched_inferred_findings(
    findings: Vec<CombinedFindingWithChain>,
) -> Vec<CombinedFindingWithChain> {
    // Pre-pass: which (lang + chain + sink_rule) lineages already
    // have a concrete (non-inferred) source covering them?
    let mut concrete_chains: AHashMap<(String, Vec<String>, String), ()> = AHashMap::new();
    let mut concrete_sink_sites: AHashMap<(String, String, u32, u32, String), ()> = AHashMap::new();
    for combined in &findings {
        let f = &combined.finding;
        if source_is_inferred(&f.source) {
            continue;
        }
        concrete_chains.insert(
            (
                f.language.clone(),
                f.chain_display.clone(),
                f.sink.rule_id.clone(),
            ),
            (),
        );
        concrete_sink_sites.insert(
            (
                f.language.clone(),
                f.sink.file.clone(),
                f.sink.line,
                f.sink.column,
                f.sink.rule_id.clone(),
            ),
            (),
        );
    }
    let keep = |combined: &CombinedFindingWithChain| -> bool {
        let f = &combined.finding;
        // Concrete sources are never dropped here.
        if !source_is_inferred(&f.source) {
            return true;
        }
        // `class_field.inherited` is synthesized per record /
        // instance-field component. It is still the only
        // available source evidence for constructor-to-field
        // flows in some languages, so only collapse it when
        // another source already covers the same chain or sink.
        let is_class_field = f.source.origin == MatchOrigin::InferredClassField;
        let is_unreferenced_entry = f.source.origin == MatchOrigin::InferredUnreferencedParameter;
        let same_sink_site_covered = concrete_sink_sites.contains_key(&(
            f.language.clone(),
            f.sink.file.clone(),
            f.sink.line,
            f.sink.column,
            f.sink.rule_id.clone(),
        ));
        if is_class_field && same_sink_site_covered {
            return false;
        }
        if is_unreferenced_entry && same_sink_site_covered {
            return false;
        }
        // Other inferred shapes may be the only upstream. Preserve
        // them unless concrete evidence already covers this exact
        // chain or sink site; in that case the field-name check
        // below can drop sibling/container over-approximations
        // without hiding the real source-rule finding.
        let same_chain_covered = {
            let key = (
                f.language.clone(),
                f.chain_display.clone(),
                f.sink.rule_id.clone(),
            );
            concrete_chains.contains_key(&key)
        };
        if !same_chain_covered && !same_sink_site_covered {
            return true;
        }
        // Source text without a field-name segment (rare) gets
        // kept; the source-preference rank demotes it anyway.
        let Some(field) = inferred_source_field_name(&f.source.text) else {
            return true;
        };
        // Compare the leaf field name against tokens extracted
        // from the sink's tainted-arg value_text. Substring-token
        // match handles `$cmd` / `cmd` / `data.cmd` uniformly.
        // Keep only the field-matching inferred sources; drop
        // the siblings that reached this chain via overtaint.
        inferred_field_mentioned_in_sink_args(&f.sink, field)
    };
    let mut kept: Vec<CombinedFindingWithChain> = Vec::new();
    // (sink site, member finding id) pairs for dropped-but-equivalent
    // inferred findings to fold into their covering concrete row.
    let mut equivalent_members: Vec<(SinkSiteKey, String)> = Vec::new();
    for combined in findings {
        if keep(&combined) {
            kept.push(combined);
            continue;
        }
        // A covered-and-dropped inferred path whose field name matches
        // the sink's tainted args is EQUIVALENT evidence for the
        // concrete row (same sink site, same tainted component) — not
        // a sibling over-approximation. Retain its finding id as a
        // member of the covering concrete row so the grouped report
        // acknowledges both the concrete and inferred paths.
        let f = &combined.finding;
        let field_matches = inferred_source_field_name(&f.source.text)
            .is_some_and(|field| inferred_field_mentioned_in_sink_args(&f.sink, field));
        if field_matches {
            equivalent_members.push((
                SinkSiteKey {
                    language: f.language.clone(),
                    file: f.sink.file.clone(),
                    line: f.sink.line,
                    column: f.sink.column,
                    rule_id: f.sink.rule_id.clone(),
                },
                f.finding_id.clone(),
            ));
        }
    }
    for (site, member_id) in equivalent_members {
        let host = kept.iter_mut().find(|combined| {
            let f = &combined.finding;
            !source_is_inferred(&f.source)
                && f.language == site.language
                && f.sink.file == site.file
                && f.sink.line == site.line
                && f.sink.column == site.column
                && f.sink.rule_id == site.rule_id
        });
        if let Some(host) = host {
            if !host.member_finding_ids.contains(&member_id) {
                host.member_finding_ids.push(member_id);
            }
        }
    }
    kept
}

/// True when `field` appears as a token inside any of the sink's
/// tainted-arg value texts (`$cmd` / `cmd` / `data.cmd` all mention
/// `cmd`).
fn inferred_field_mentioned_in_sink_args(sink: &FindingMatch, field: &str) -> bool {
    let sink_arg_text = sink
        .tainted_args
        .iter()
        .map(|arg| arg.value_text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    sink_arg_text
        .split(|c: char| !(c == '_' || c.is_ascii_alphanumeric()))
        .any(|t| t == field)
}

fn source_is_inferred(source: &FindingMatch) -> bool {
    matches!(
        source.origin,
        MatchOrigin::InferredUnreferencedParameter
            | MatchOrigin::InferredFrameworkParameter
            | MatchOrigin::InferredClassField
    )
}

/// Extract the leaf field-name from an inferred source's `text` —
/// the final identifier token, regardless of the member-access
/// operator or sigil that precedes it: `this.cmd` / `self.cmd` /
/// `this->cmd` (C/C++) / `$this->cmd` (PHP) / `self::cmd` (Rust) /
/// `envelope.data.cmd` all yield `cmd`. The leaf is the actual field
/// the inferred-source generator named; the parent path is the
/// container chain we project through.
///
/// We scan the trailing run of identifier characters rather than
/// splitting on `.` alone, so `->` / `::` / `$` separators are all
/// handled uniformly (a `.`-only split left C/C++ `this->cmd` intact
/// and mis-matched it against the sink's `cmd` arg).
fn inferred_source_field_name(text: &str) -> Option<&str> {
    let trimmed = text.trim();
    // Walk back from the end collecting the final identifier run.
    let mut start = trimmed.len();
    for (idx, ch) in trimmed.char_indices().rev() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            start = idx;
        } else {
            break;
        }
    }
    let tail = &trimmed[start..];
    // Reject an empty or digit-leading tail (not a field identifier).
    if !tail
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    {
        return None;
    }
    Some(tail)
}

/// Trust-based source preference, modulated by the sink the source
/// reaches when known. The flat trust-rank ("remote" beats "local"
/// always) systematically mis-attributes mega_flow-shape chains
/// where two sources co-taint a container and only one of them
/// semantically feeds the sink's matched arg — e.g. PHP's
/// `['cmd' => $raw, 'user' => $_SERVER, ...]` puts both readline
/// (`local`) and `$_SERVER` (`remote`) into `$envelope`, and the
/// downstream `shell_exec($cmd)` sink reaches both. The cmd-channel
/// source is `readline`, but the flat rank picks `$_SERVER` because
/// remote-trust outranks local-trust. Use sink semantics
/// (`category`/`tag`) to break that tie when the rule pack tells us
/// which input shape is the natural carrier for that sink class.
fn finding_has_flow_class(pack: &Rulepack, finding: &FindingMatch, class: FlowClass) -> bool {
    pack.find_rule_by_id(&finding.rule_id)
        .and_then(|rule| rule.analysis_semantics.as_ref())
        .is_some_and(|semantics| semantics.flow_classes.contains(&class))
}

fn source_preference_rank_for_sink(
    pack: &Rulepack,
    source: &FindingMatch,
    sink: Option<&FindingMatch>,
) -> u8 {
    if source_is_inferred(source) {
        return 30;
    }
    let base = match source.trust.as_deref() {
        Some("remote") => 0,
        Some("service" | "ipc" | "database" | "library") => 5,
        Some("local" | "config" | "physical") => 10,
        _ => 15,
    };
    let Some(sink) = sink else { return base };
    let sink_is_process = finding_has_flow_class(pack, sink, FlowClass::ProcessExecution);
    let sink_is_browser = finding_has_flow_class(pack, sink, FlowClass::BrowserOutput);
    let src_is_process_or_cli = finding_has_flow_class(pack, source, FlowClass::ProcessInput);
    let src_is_http = finding_has_flow_class(pack, source, FlowClass::HttpInput);
    // Adjustment magnitude is one full trust tier (10) so a semantic
    // match against the sink can flip the abstract trust order — e.g.
    // a `local`-trust cli source ranks ABOVE a `remote`-trust http
    // source when the sink is cmd-injection. Match-side promote AND
    // mismatch-side penalize, so the gap is the full 20.
    let mut adjusted = base as i16;
    if sink_is_process {
        // Process / cmdi sink: prefer cli/stdin/file sources, demote
        // pure-http sources that only co-tainted through a container.
        if src_is_process_or_cli {
            adjusted -= 10;
        }
        if src_is_http && !src_is_process_or_cli {
            adjusted += 10;
        }
    }
    if sink_is_browser {
        // xss / browser sink: prefer http sources, demote pure-cli
        // sources that only co-tainted through a container.
        if src_is_http {
            adjusted -= 10;
        }
        if src_is_process_or_cli && !src_is_http {
            adjusted += 10;
        }
    }
    adjusted.clamp(0, 255) as u8
}

fn source_specificity_rank(pack: &Rulepack, source: &FindingMatch) -> u8 {
    pack.find_rule_by_id(&source.rule_id)
        .and_then(|rule| rule.analysis_semantics.as_ref())
        .and_then(|semantics| semantics.source_specificity_rank)
        .unwrap_or(2)
}

fn source_reporting_rank(pack: &Rulepack, source: &FindingMatch) -> u8 {
    pack.find_rule_by_id(&source.rule_id)
        .and_then(|rule| rule.analysis_semantics.as_ref())
        .and_then(|semantics| semantics.source_reporting_rank)
        .unwrap_or(0)
}

fn source_rule_allows_sink_tag(pack: &Rulepack, source_rule_id: &str, sink_rule: &Rule) -> bool {
    let Some(source_rule) = pack.find_rule_by_id(source_rule_id) else {
        return true;
    };
    source_rule.constraints.iter().all(|constraint| match constraint {
        ConstraintKind::SinkTagIn { sink_tag_in } => sink_rule
            .tag
            .as_deref()
            .is_some_and(|tag| sink_tag_in.iter().any(|allowed| allowed == tag)),
        _ => true,
    })
}

/// True when two sink-side `FindingMatch`es refer to the exact same
/// call-site. Symmetric counterpart to [`same_source_site`].
fn same_sink_site(a: &FindingMatch, b: &FindingMatch) -> bool {
    a.rule_id == b.rule_id && a.file == b.file && a.line == b.line && a.column == b.column
}

#[cfg(test)]
fn combine_findings_by_source_flow(
    findings: Vec<FindingWithChain>,
    pack: &Rulepack,
) -> Vec<CombinedFindingWithChain> {
    combine_route_findings_by_sink(
        findings.into_iter().map(combined_from_raw_finding).collect(),
        pack,
    )
}

fn combined_from_raw_finding(item: FindingWithChain) -> CombinedFindingWithChain {
    CombinedFindingWithChain {
        finding: item.finding,
        chain_funcs: item.chain_funcs,
        additional_sources: Vec::new(),
        additional_sinks: Vec::new(),
        member_finding_ids: Vec::new(),
    }
}

fn combine_route_findings_by_sink(
    mut findings: Vec<CombinedFindingWithChain>,
    pack: &Rulepack,
) -> Vec<CombinedFindingWithChain> {
    let mut groups: Vec<CombinedFindingWithChain> = Vec::new();
    let mut index: AHashMap<String, usize> = AHashMap::new();

    // Stable-sort so that within each semantic sink-site bucket — which is
    // what `combined_finding_key` collapses into one group — the preferred,
    // broadest proven route becomes the primary. Every other complete route
    // remains attached as an `alternate_flow`.
    //
    // The first route remains the primary route throughout finalization, so
    // this ordering owns both source preference and source/path coherence.
    // Within a bucket every member shares the same sink site and class.
    findings.sort_by(|a, b| {
        // Sort bucket MUST match `combined_finding_key`'s grouping
        // dimensions (evidence kind + language + sink class + exact site).
        let bucket_a = (
            &a.finding.language,
            finding_is_pattern_evidence(&a.finding),
            &a.finding.sink.file,
            a.finding.sink.line,
            a.finding.sink.column,
            sink_group_class(&a.finding.sink),
            a.finding.sink.text.as_str(),
        );
        let bucket_b = (
            &b.finding.language,
            finding_is_pattern_evidence(&b.finding),
            &b.finding.sink.file,
            b.finding.sink.line,
            b.finding.sink.column,
            sink_group_class(&b.finding.sink),
            b.finding.sink.text.as_str(),
        );
        bucket_a
            .cmp(&bucket_b)
            .then_with(|| primary_status_rank(a.finding.status).cmp(&primary_status_rank(b.finding.status)))
            .then_with(|| {
                source_preference_rank_for_sink(pack, &a.finding.source, Some(&a.finding.sink)).cmp(
                    &source_preference_rank_for_sink(pack, &b.finding.source, Some(&b.finding.sink)),
                )
            })
            .then_with(|| {
                source_specificity_rank(pack, &a.finding.source)
                    .cmp(&source_specificity_rank(pack, &b.finding.source))
            })
            .then_with(|| {
                source_reporting_rank(pack, &a.finding.source)
                    .cmp(&source_reporting_rank(pack, &b.finding.source))
            })
            .then_with(|| b.chain_funcs.len().cmp(&a.chain_funcs.len()))
            .then_with(|| finding_route_taint_width(&a.finding).cmp(&finding_route_taint_width(&b.finding)))
            .then_with(|| {
                (
                    a.finding.source.file.as_str(),
                    a.finding.source.line,
                    a.finding.source.column,
                )
                    .cmp(&(
                        b.finding.source.file.as_str(),
                        b.finding.source.line,
                        b.finding.source.column,
                    ))
            })
            .then_with(|| a.finding.source.rule_id.cmp(&b.finding.source.rule_id))
    });

    bonsai_diagnostics::debug_log!(
        "find-group",
        "combining {} raw finding(s) into groups",
        findings.len()
    );
    for item in findings {
        let key = combined_finding_key(&item);
        bonsai_diagnostics::debug_log!(
            "find-group",
            "  finding {} src={} sink={}@{}:{} -> key={:?}",
            item.finding.finding_id,
            item.finding.source.rule_id,
            item.finding.sink.rule_id,
            item.finding.sink.file,
            item.finding.sink.line,
            key
        );
        if let Some(&idx) = index.get(&key) {
            bonsai_diagnostics::debug_log!(
                "find-group",
                "    -> merge into existing group #{} (primary={})",
                idx,
                groups[idx].finding.finding_id
            );
            merge_combined_finding_into_group(&mut groups[idx], item);
            continue;
        }
        let idx = groups.len();
        index.insert(key, idx);
        groups.push(item);
    }

    for group in &mut groups {
        finalize_combined_finding(group);
    }
    groups
}

fn primary_status_rank(status: FindingStatus) -> u8 {
    match status {
        FindingStatus::Unsanitized => 0,
        FindingStatus::WrongContext => 1,
        FindingStatus::Sanitized => 2,
    }
}

fn combined_finding_key(item: &CombinedFindingWithChain) -> String {
    let f = &item.finding;
    let sink_class = sink_group_class(&f.sink);
    // Key on (language, SINK CLASS + exact SITE). Sink site =
    // file + line + column + sink text; sink class is
    // the rule tag/category, falling back to rule id for unclassified
    // rules. This keeps different vulnerability classes separate at
    // the same line while collapsing alias rules that describe the
    // same semantic edge (`cursor.execute`, abbreviated cursor, typed
    // cursor) into one finding.
    //
    // Source and flow ids identify routes, not vulnerabilities. All complete
    // routes remain available through the primary route plus
    // `alternate_flows`.
    format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}",
        f.language,
        finding_is_pattern_evidence(f),
        f.sink.file,
        f.sink.line,
        f.sink.column,
        sink_class,
        f.sink.text
    )
}

fn finding_is_pattern_evidence(finding: &Finding) -> bool {
    finding.source.origin == MatchOrigin::Pattern
}

fn extend_implicit_context_findings(
    findings: &mut Vec<FindingWithChain>,
    sink_hits: &[RuleMatch],
    pack: &Rulepack,
    ws: &Workspace,
) {
    let context_consumers: Vec<(&Rule, &RuleMatch)> = sink_hits
        .iter()
        .filter_map(|hit| {
            let rule = pack.find_rule_by_id(&hit.rule_id)?;
            let context = rule.analysis_semantics.as_ref()?.context_flow.as_ref()?;
            (context.role == ContextFlowRole::Consumer).then_some((rule, hit))
        })
        .collect();
    if context_consumers.is_empty() {
        return;
    }

    let producer_flows: Vec<FindingWithChain> = findings
        .iter()
        .filter(|item| {
            item.finding.status == FindingStatus::Unsanitized
                && pack
                    .find_rule_by_id(&item.finding.sink.rule_id)
                    .and_then(|rule| rule.analysis_semantics.as_ref())
                    .and_then(|semantics| semantics.context_flow.as_ref())
                    .is_some_and(|context| context.role == ContextFlowRole::Producer)
        })
        .cloned()
        .collect();
    if producer_flows.is_empty() {
        return;
    }

    let mut existing_ids: AHashSet<String> = findings
        .iter()
        .map(|item| item.finding.finding_id.clone())
        .collect();
    let mut consumed_producer_finding_ids: AHashSet<String> = AHashSet::new();
    for producer_flow in producer_flows {
        let Some(producer_context) = pack
            .find_rule_by_id(&producer_flow.finding.sink.rule_id)
            .and_then(|rule| rule.analysis_semantics.as_ref())
            .and_then(|semantics| semantics.context_flow.as_ref())
        else {
            continue;
        };
        let mut emitted_for_producer = false;
        for &(sink_rule, consumer_sink) in &context_consumers {
            let Some(consumer_context) = sink_rule
                .analysis_semantics
                .as_ref()
                .and_then(|semantics| semantics.context_flow.as_ref())
            else {
                continue;
            };
            if consumer_context.channel != producer_context.channel
                || consumer_sink.language != producer_flow.finding.language
            {
                continue;
            }
            let mut sink_match = FindingMatch::from_rule_match(consumer_sink, sink_rule);
            sink_match.tainted_args.push(TaintedArgInfo {
                index: usize::MAX,
                value_text: consumer_context.value_label.clone(),
                ..TaintedArgInfo::default()
            });

            let mut chain_display = producer_flow.finding.chain_display.clone();
            if let Some(sink_fn) = consumer_sink.enclosing_fn.as_ref() {
                if !chain_display.iter().any(|name| name == sink_fn) {
                    chain_display.push(sink_fn.clone());
                }
            }

            let mut chain_funcs = producer_flow.chain_funcs.clone();
            if let Some(sink_func) = func_id_for_match(ws, consumer_sink) {
                if !chain_funcs.contains(&sink_func) {
                    chain_funcs.push(sink_func);
                }
            }

            let mut taint_path = producer_flow.finding.taint_path.clone();
            taint_path.push(TaintPropagationStep {
                caller: consumer_sink
                    .enclosing_fn
                    .clone()
                    .unwrap_or_else(|| "<context-consumer>".to_string()),
                callee: consumer_sink.match_text.clone(),
                file: consumer_sink.file.clone(),
                line: consumer_sink.line,
                column: consumer_sink.column,
                tainted_args: vec![TaintPropagationArg {
                    index: usize::MAX,
                    value_text: consumer_context.value_label.clone(),
                    param_name: consumer_context.parameter_name.clone(),
                }],
            });

            let group_id = group_id_for_taint_path(&chain_display, &taint_path);
            let flow_id = flow_id_for_taint_path(&chain_display, &taint_path);
            let source_identity = finding_match_identity_token(&producer_flow.finding.source);
            let sink_identity = finding_match_identity_token(&sink_match);
            let finding_id = compute_finding_id(
                &source_identity,
                &sink_identity,
                &group_id,
                &producer_flow.finding.language,
            );
            if !existing_ids.insert(finding_id.clone()) {
                continue;
            }

            let root = ws.db().workspace_root();
            let from_test = path_is_test_file_with_root(root.as_deref(), &producer_flow.finding.source.file)
                || path_is_test_file_with_root(root.as_deref(), &sink_match.file)
                || taint_path
                    .iter()
                    .any(|step| path_is_test_file_with_root(root.as_deref(), &step.file));

            findings.push(FindingWithChain {
                finding: Finding {
                    finding_id,
                    language: producer_flow.finding.language.clone(),
                    source: producer_flow.finding.source.clone(),
                    sink: sink_match,
                    sanitizers_seen: producer_flow.finding.sanitizers_seen.clone(),
                    group_id: Some(group_id),
                    representative_flow_id: Some(flow_id),
                    analysis_complete: producer_flow.finding.analysis_complete,
                    analysis_incomplete_reasons: producer_flow.finding.analysis_incomplete_reasons.clone(),
                    chain_display,
                    taint_path,
                    alternate_flows: Vec::new(),
                    hops: Vec::new(),
                    tag: sink_rule.tag.clone(),
                    severity: sink_rule.severity,
                    precision: precision_label(Precision::Narrowed).to_string(),
                    cwe: sink_rule.cwe.clone(),
                    owasp: sink_rule.owasp.clone(),
                    status: FindingStatus::Unsanitized,
                    from_test,
                },
                chain_funcs,
            });
            emitted_for_producer = true;
        }
        if emitted_for_producer {
            consumed_producer_finding_ids.insert(producer_flow.finding.finding_id);
        }
    }
    if !consumed_producer_finding_ids.is_empty() {
        findings.retain(|item| !consumed_producer_finding_ids.contains(&item.finding.finding_id));
    }
}

fn sink_group_class(sink: &FindingMatch) -> &str {
    sink.tag
        .as_deref()
        .or(sink.category.as_deref())
        .unwrap_or(sink.rule_id.as_str())
}

fn merge_combined_finding_into_group(
    group: &mut CombinedFindingWithChain,
    mut incoming: CombinedFindingWithChain,
) {
    let member_id = incoming.finding.finding_id.clone();
    let additional_sources = std::mem::take(&mut incoming.additional_sources);
    let additional_sinks = std::mem::take(&mut incoming.additional_sinks);
    let member_finding_ids = std::mem::take(&mut incoming.member_finding_ids);
    merge_finding_into_group(group, incoming.finding, member_id);

    for source in additional_sources {
        if !same_source_site(&group.finding.source, &source)
            && !group
                .additional_sources
                .iter()
                .any(|existing| same_source_site(existing, &source))
        {
            group.additional_sources.push(source);
        }
    }
    for sink in additional_sinks {
        if !same_sink_site(&group.finding.sink, &sink)
            && !group
                .additional_sinks
                .iter()
                .any(|existing| same_sink_site(existing, &sink))
        {
            group.additional_sinks.push(sink);
        }
    }
    for member_id in member_finding_ids {
        if member_id != group.finding.finding_id && !group.member_finding_ids.contains(&member_id) {
            group.member_finding_ids.push(member_id);
        }
    }
}

fn merge_finding_into_group(group: &mut CombinedFindingWithChain, mut incoming: Finding, member_id: String) {
    if group.finding.finding_id != member_id && !group.member_finding_ids.contains(&member_id) {
        group.member_finding_ids.push(member_id);
    }
    if !same_source_site(&group.finding.source, &incoming.source)
        && !group
            .additional_sources
            .iter()
            .any(|source| same_source_site(source, &incoming.source))
    {
        group.additional_sources.push(incoming.source.clone());
    }
    let incoming_flow = AlternateTaintFlow {
        source: incoming.source.clone(),
        sink_tainted_args: incoming.sink.tainted_args.clone(),
        sanitizers_seen: incoming.sanitizers_seen.clone(),
        flow_id: incoming.representative_flow_id.clone(),
        chain_display: incoming.chain_display.clone(),
        taint_path: incoming.taint_path.clone(),
        status: incoming.status,
        precision: incoming.precision.clone(),
    };
    if incoming_flow.flow_id != group.finding.representative_flow_id
        && !group
            .finding
            .alternate_flows
            .iter()
            .any(|flow| flow.flow_id == incoming_flow.flow_id)
    {
        group.finding.alternate_flows.push(incoming_flow);
    }
    for flow in std::mem::take(&mut incoming.alternate_flows) {
        if flow.flow_id != group.finding.representative_flow_id
            && !group
                .finding
                .alternate_flows
                .iter()
                .any(|existing| existing.flow_id == flow.flow_id)
        {
            group.finding.alternate_flows.push(flow);
        }
    }
    if !same_sink_site(&group.finding.sink, &incoming.sink)
        && !group
            .additional_sinks
            .iter()
            .any(|sink| same_sink_site(sink, &incoming.sink))
    {
        group.additional_sinks.push(incoming.sink.clone());
    }
    group.finding.severity = max_severity(group.finding.severity, incoming.severity);
    group.finding.tag = merge_tag(group.finding.tag.clone(), incoming.tag.as_deref());
    merge_unique(&mut group.finding.cwe, incoming.cwe);
    merge_unique(&mut group.finding.owasp, incoming.owasp);
    merge_analysis_completeness(
        &mut group.finding.analysis_complete,
        &mut group.finding.analysis_incomplete_reasons,
        incoming.analysis_complete,
        incoming.analysis_incomplete_reasons,
    );
    group.finding.from_test &= incoming.from_test;
    // Status merge: the LEAST-mitigated chain wins. If any chain in
    // this group is unsanitized, the group is unsanitized — finding a
    // sanitizer on one path doesn't make the others safe.
    group.finding.status = group.finding.status.merge(incoming.status);
}

fn merge_analysis_completeness(
    current_complete: &mut bool,
    current_reasons: &mut Vec<String>,
    incoming_complete: bool,
    incoming_reasons: Vec<String>,
) {
    if !incoming_complete {
        *current_complete = false;
    }
    merge_unique(current_reasons, incoming_reasons);
    current_reasons.sort();
    current_reasons.dedup();
    if !current_reasons.is_empty() {
        *current_complete = false;
    }
}

fn finalize_combined_finding(group: &mut CombinedFindingWithChain) {
    if !group.member_finding_ids.contains(&group.finding.finding_id) {
        group
            .member_finding_ids
            .insert(0, group.finding.finding_id.clone());
    }
    // Keep the primary route's sink match paired with its source, path, and
    // tainted arguments. Alias rules at the same semantic site remain
    // available as additional sinks and contribute severity/taxonomy during
    // merge, but must not replace the route-specific primary match.
    group.additional_sinks.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| (a.file.as_str(), a.line, a.column).cmp(&(b.file.as_str(), b.line, b.column)))
    });

    // The primary source stays pinned to the first-seen bucket member.
    // `combine_route_findings_by_sink` pre-sorts findings so the preferred
    // source (concrete rulepack sources rank ahead of inferred entry-point
    // placeholders via `source_preference_rank_for_sink`) is seen first, and
    // `merge_finding_into_group` retains that same member's flow evidence
    // (`taint_path`, `representative_flow_id`, `chain_display`). Re-deriving a
    // different primary here — as an earlier version did by re-ranking every
    // co-tainted source against the group's severity-max sink — can promote a
    // source whose evidence was NOT retained, so the reported source would
    // never appear on the reported taint path (the exact "mixed row" the
    // grouping key is designed to prevent). Keep the primary and surface
    // co-tainted sources in a stable display order. Each source's path remains
    // paired with it in `alternate_flows`.
    let primary_source = group.finding.source.clone();
    let mut additional_sources: Vec<FindingMatch> = std::mem::take(&mut group.additional_sources)
        .into_iter()
        .filter(|source| !same_source_site(&primary_source, source))
        .collect();
    additional_sources.sort_by(|a, b| {
        (a.file.as_str(), a.line, a.column)
            .cmp(&(b.file.as_str(), b.line, b.column))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    group.additional_sources = additional_sources;
    group.finding.alternate_flows.sort_by(|a, b| {
        alternate_route_taint_width(a)
            .cmp(&alternate_route_taint_width(b))
            .then_with(|| a.flow_id.cmp(&b.flow_id))
            .then_with(|| a.source.file.cmp(&b.source.file))
            .then_with(|| a.source.line.cmp(&b.source.line))
            .then_with(|| a.source.column.cmp(&b.source.column))
            .then_with(|| a.source.rule_id.cmp(&b.source.rule_id))
    });
    let primary_route = AlternateTaintFlow {
        source: group.finding.source.clone(),
        sink_tainted_args: group.finding.sink.tainted_args.clone(),
        sanitizers_seen: group.finding.sanitizers_seen.clone(),
        flow_id: group.finding.representative_flow_id.clone(),
        chain_display: group.finding.chain_display.clone(),
        taint_path: group.finding.taint_path.clone(),
        status: group.finding.status,
        precision: group.finding.precision.clone(),
    };
    let mut retained_routes: Vec<AlternateTaintFlow> = Vec::new();
    for route in std::mem::take(&mut group.finding.alternate_flows) {
        if route.flow_id == primary_route.flow_id
            || route_is_argument_superset_of(&route, &primary_route)
            || retained_routes
                .iter()
                .any(|kept| route_is_argument_superset_of(&route, kept))
        {
            continue;
        }
        retained_routes.push(route);
    }
    group.finding.alternate_flows = retained_routes;

    let group_id = group
        .finding
        .group_id
        .clone()
        .unwrap_or_else(|| group.finding.representative_flow_id.clone().unwrap_or_default());
    let sink_token = all_sink_matches(group)
        .iter()
        .map(finding_match_identity_token)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join("+");
    let source_token = all_source_matches(group)
        .iter()
        .map(finding_match_identity_token)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join("+");
    group.finding.finding_id =
        compute_finding_id(&source_token, &sink_token, &group_id, &group.finding.language);
    group.member_finding_ids.sort();
    group.member_finding_ids.dedup();
}

fn all_source_matches(group: &CombinedFindingWithChain) -> Vec<FindingMatch> {
    let mut sources = Vec::with_capacity(1 + group.additional_sources.len());
    sources.push(group.finding.source.clone());
    sources.extend(group.additional_sources.iter().cloned());
    sources
}

fn all_sink_matches(group: &CombinedFindingWithChain) -> Vec<FindingMatch> {
    let mut sinks = Vec::with_capacity(1 + group.additional_sinks.len());
    sinks.push(group.finding.sink.clone());
    sinks.extend(group.additional_sinks.iter().cloned());
    sinks
}

fn finding_route_taint_width(finding: &Finding) -> usize {
    finding
        .taint_path
        .iter()
        .map(|step| step.tainted_args.len())
        .sum::<usize>()
        .saturating_add(finding.sink.tainted_args.len())
}

fn alternate_route_taint_width(flow: &AlternateTaintFlow) -> usize {
    flow.taint_path
        .iter()
        .map(|step| step.tainted_args.len())
        .sum::<usize>()
        .saturating_add(flow.sink_tainted_args.len())
}

/// True when `broader` is the same source and call route as `narrower`, but
/// carries a strict superset of tainted arguments. The compiler graph keeps
/// both proofs; presentation retains the narrower one because the broader
/// route adds no source/sink reachability and can only reduce precision.
fn route_is_argument_superset_of(broader: &AlternateTaintFlow, narrower: &AlternateTaintFlow) -> bool {
    if !same_source_site(&broader.source, &narrower.source)
        || broader.chain_display != narrower.chain_display
        || broader.taint_path.len() != narrower.taint_path.len()
    {
        return false;
    }
    let same_sites = broader
        .taint_path
        .iter()
        .zip(&narrower.taint_path)
        .all(|(broad, narrow)| {
            broad.caller == narrow.caller
                && broad.callee == narrow.callee
                && broad.file == narrow.file
                && broad.line == narrow.line
                && broad.column == narrow.column
        });
    if !same_sites {
        return false;
    }
    let path_is_superset = broader
        .taint_path
        .iter()
        .zip(&narrower.taint_path)
        .all(|(broad, narrow)| propagation_args_are_subset(&narrow.tainted_args, &broad.tainted_args));
    let sink_is_superset =
        tainted_arg_infos_are_subset(&narrower.sink_tainted_args, &broader.sink_tainted_args);
    let strictly_broader = alternate_route_taint_width(broader) > alternate_route_taint_width(narrower);
    path_is_superset && sink_is_superset && strictly_broader
}

fn propagation_args_are_subset(subset: &[TaintPropagationArg], superset: &[TaintPropagationArg]) -> bool {
    subset.iter().all(|item| {
        superset.iter().any(|candidate| {
            candidate.index == item.index
                && candidate.value_text == item.value_text
                && candidate.param_name == item.param_name
        })
    })
}

fn tainted_arg_infos_are_subset(subset: &[TaintedArgInfo], superset: &[TaintedArgInfo]) -> bool {
    subset.iter().all(|item| {
        superset.iter().any(|candidate| {
            candidate.index == item.index
                && candidate.value_text == item.value_text
                && candidate.place == item.place
                && candidate.source_names == item.source_names
        })
    })
}

/// Keep the rulepack-designated security boundary when the exact same source
/// flow continues into a lower-priority transport sink.
///
/// This is deliberately stricter than tag-based deduplication: the preferred
/// finding must have a higher declared terminal priority and its compiler
/// function chain must be a proper prefix of the downstream finding's chain.
/// Sibling sinks, equal-length paths, and unrelated flows therefore remain
/// independently reportable.
fn drop_rulepack_terminal_dominated_findings(findings: &mut Vec<CombinedFindingWithChain>, pack: &Rulepack) {
    if findings.len() < 2 {
        return;
    }
    let mut dominated = AHashSet::new();
    for (idx, downstream) in findings.iter().enumerate() {
        if findings.iter().enumerate().any(|(other_idx, preferred)| {
            other_idx != idx && terminal_finding_dominates(preferred, downstream, pack)
        }) {
            dominated.insert(idx);
        }
    }
    if dominated.is_empty() {
        return;
    }
    let mut next_idx = 0usize;
    findings.retain(|_| {
        let keep = !dominated.contains(&next_idx);
        next_idx = next_idx.saturating_add(1);
        keep
    });
}

fn terminal_finding_dominates(
    preferred: &CombinedFindingWithChain,
    downstream: &CombinedFindingWithChain,
    pack: &Rulepack,
) -> bool {
    let preferred_finding = &preferred.finding;
    let downstream_finding = &downstream.finding;
    let preferred_priority = sink_terminal_priority(pack, preferred);
    let downstream_priority = sink_terminal_priority(pack, downstream);

    preferred_priority > downstream_priority
        && preferred_priority > 0
        && preferred_finding.language == downstream_finding.language
        && preferred_finding.tag == downstream_finding.tag
        && preferred_finding.status == downstream_finding.status
        && same_source_site(&preferred_finding.source, &downstream_finding.source)
        && cwe_sets_overlap_or_unknown(&preferred_finding.cwe, &downstream_finding.cwe)
        && function_chain_is_strict_prefix(&preferred.chain_funcs, &downstream.chain_funcs)
}

fn sink_terminal_priority(pack: &Rulepack, finding: &CombinedFindingWithChain) -> u8 {
    all_sink_matches(finding)
        .into_iter()
        .filter_map(|sink| {
            pack.find_rule_by_id(&sink.rule_id)
                .and_then(|rule| rule.analysis_semantics.as_ref())
                .and_then(|semantics| semantics.sink_terminal_priority)
        })
        .max()
        .unwrap_or(0)
}

fn function_chain_is_strict_prefix(prefix: &[FuncId], chain: &[FuncId]) -> bool {
    !prefix.is_empty() && chain.len() > prefix.len() && chain.starts_with(prefix)
}

/// Prefer the semantic sink inside a nested call over the transport
/// wrapper that merely sends that nested result. Example:
/// `res.end(renderResults(q))` and `renderResults -> return "<div>"+q`
/// are both true facts, but reporting both makes cross-file cases look
/// truncated when rankers read the first result. Drop the wrapper only
/// when a same-source, same-class deeper flow starts at the nested
/// callee on the same call-site line.
fn drop_dominated_wrapper_findings(findings: &mut Vec<CombinedFindingWithChain>) {
    if findings.len() < 2 {
        return;
    }
    let mut dominated = AHashSet::new();
    for (idx, candidate) in findings.iter().enumerate() {
        if findings
            .iter()
            .enumerate()
            .any(|(other_idx, other)| other_idx != idx && wrapper_finding_is_dominated(candidate, other))
        {
            dominated.insert(idx);
        }
    }
    if dominated.is_empty() {
        return;
    }
    let mut next_idx = 0usize;
    findings.retain(|_| {
        let keep = !dominated.contains(&next_idx);
        next_idx = next_idx.saturating_add(1);
        keep
    });
}

fn drop_dominated_receiver_projection_findings(findings: &mut Vec<CombinedFindingWithChain>) {
    if findings.len() < 2 {
        return;
    }
    let mut dominated = AHashSet::new();
    for (idx, candidate) in findings.iter().enumerate() {
        if findings.iter().enumerate().any(|(other_idx, other)| {
            other_idx != idx && receiver_projection_finding_is_dominated(candidate, other)
        }) {
            dominated.insert(idx);
        }
    }
    if dominated.is_empty() {
        return;
    }
    let mut next_idx = 0usize;
    findings.retain(|_| {
        let keep = !dominated.contains(&next_idx);
        next_idx = next_idx.saturating_add(1);
        keep
    });
}

fn receiver_projection_finding_is_dominated(
    receiver_projection: &CombinedFindingWithChain,
    direct_arg: &CombinedFindingWithChain,
) -> bool {
    let projected = &receiver_projection.finding;
    let direct = &direct_arg.finding;
    projected.language == direct.language
        && projected.tag == direct.tag
        && projected.status == direct.status
        && same_source_site(&projected.source, &direct.source)
        && same_sink_site(&projected.sink, &direct.sink)
        && cwe_sets_overlap_or_unknown(&projected.cwe, &direct.cwe)
        && sink_args_are_receiver_projection_only(&projected.sink.tainted_args)
        && sink_args_include_direct_argument(&direct.sink.tainted_args)
}

fn sink_args_are_receiver_projection_only(args: &[TaintedArgInfo]) -> bool {
    !args.is_empty() && args.iter().all(|arg| arg.index == usize::MAX)
}

fn sink_args_include_direct_argument(args: &[TaintedArgInfo]) -> bool {
    args.iter().any(|arg| arg.index != usize::MAX)
}

fn wrapper_finding_is_dominated(
    wrapper: &CombinedFindingWithChain,
    deeper: &CombinedFindingWithChain,
) -> bool {
    let wrapper_finding = &wrapper.finding;
    let deeper_finding = &deeper.finding;
    if wrapper_finding.language != deeper_finding.language
        || wrapper_finding.tag != deeper_finding.tag
        || wrapper_finding.status != deeper_finding.status
        || !same_source_site(&wrapper_finding.source, &deeper_finding.source)
        || !cwe_sets_overlap_or_unknown(&wrapper_finding.cwe, &deeper_finding.cwe)
        || deeper_finding.chain_display.len() <= wrapper_finding.chain_display.len()
        || !chain_has_prefix(&deeper_finding.chain_display, &wrapper_finding.chain_display)
        || wrapper_finding.taint_path.len() != 1
        || deeper_finding.taint_path.is_empty()
    {
        return false;
    }

    let wrapper_step = &wrapper_finding.taint_path[0];
    let deeper_entry = &deeper_finding.taint_path[0];
    if wrapper_step.file != deeper_entry.file
        || wrapper_step.line != deeper_entry.line
        || wrapper_step.caller != deeper_entry.caller
    {
        return false;
    }

    let nested_callee = display_callee_tail(&deeper_entry.callee);
    if nested_callee.is_empty() {
        return false;
    }
    wrapper_finding
        .sink
        .tainted_args
        .iter()
        .any(|arg| argument_text_calls(&arg.value_text, &nested_callee))
        || wrapper_step
            .tainted_args
            .iter()
            .any(|arg| argument_text_calls(&arg.value_text, &nested_callee))
}

fn chain_has_prefix(chain: &[String], prefix: &[String]) -> bool {
    !prefix.is_empty() && chain.len() > prefix.len() && chain.iter().zip(prefix).all(|(a, b)| a == b)
}

fn cwe_sets_overlap_or_unknown(left: &[String], right: &[String]) -> bool {
    left.is_empty() || right.is_empty() || left.iter().any(|item| right.iter().any(|other| other == item))
}

fn display_callee_tail(name: &str) -> String {
    let without_site = name.split('@').next().unwrap_or(name);
    without_site
        .rsplit(['.', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(without_site)
        .trim()
        .trim_end_matches("()")
        .to_string()
}

fn argument_text_calls(argument: &str, callee: &str) -> bool {
    let callee = callee.trim();
    if callee.is_empty() {
        return false;
    }
    let compact_arg: String = argument.chars().filter(|ch| !ch.is_whitespace()).collect();
    let compact_callee: String = callee.chars().filter(|ch| !ch.is_whitespace()).collect();
    compact_arg.contains(&format!("{compact_callee}("))
}

/// Pick the higher severity from two optionals, or the only present
/// one. None when both are absent.
fn max_severity(a: Option<Severity>, b: Option<Severity>) -> Option<Severity> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Combine two finding tags during group merge. Identical tags pass
/// through; conflicting tags collapse to the catch-all `"multiple"`
/// label so the renderer can show "this group covers more than one
/// vulnerability class".
fn merge_tag(current: Option<String>, incoming: Option<&str>) -> Option<String> {
    match (current, incoming) {
        (None, None) => None,
        (Some(tag), None) => Some(tag),
        (None, Some(tag)) => Some(tag.to_string()),
        (Some(tag), Some(next)) if tag == next => Some(tag),
        (Some(_), Some(_)) => Some("multiple".to_string()),
    }
}

/// Append `src` onto `dst`, skipping duplicates. O(n²) but the
/// vectors are small enough (CWE / OWASP / sanitizer-id lists
/// rarely exceed 10 entries) that a hash detour costs more than it
/// saves.
fn merge_unique(dst: &mut Vec<String>, src: Vec<String>) {
    for value in src {
        if !dst.contains(&value) {
            dst.push(value);
        }
    }
}

/// True when `source_span` and `sink_span` both sit inside the body of
/// one common loop in `sink_func`. A loop's back-edge makes intra-function
/// ordering non-linear: a source that textually follows the sink can still
/// taint the *next* iteration's sink, e.g.
/// `for (…) { exec(v); v = req.query.q; }`. `source_can_precede_sink`
/// otherwise rejects `src.line > snk.line`, dropping these loop-carried
/// flows as "backwards in time". Detecting a shared enclosing loop restores
/// them without loosening the strict forward-order rule elsewhere.
fn spans_share_enclosing_loop(ws: &Workspace, sink_func: FuncId, source_span: Span, sink_span: Span) -> bool {
    let Some(decl) = ws.exact_decl(SymbolId::new(sink_func.raw())) else {
        return false;
    };
    spans_share_enclosing_loop_in_events(&decl.flow_events, source_span, sink_span)
}

fn spans_share_enclosing_loop_in_events(
    events: &[bonsai_lang_api::FlowEvent],
    source_span: Span,
    sink_span: Span,
) -> bool {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Loop { span, body, .. } => {
                // A loop whose span brackets both endpoints carries the flow
                // across its back-edge. Recurse first so the *innermost*
                // shared loop is what we credit (harmless either way, but
                // keeps the match tight and lets deeper loops win).
                if spans_share_enclosing_loop_in_events(body, source_span, sink_span) {
                    return true;
                }
                if span_contains(*span, source_span) && span_contains(*span, sink_span) {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if spans_share_enclosing_loop_in_events(then_events, source_span, sink_span)
                    || spans_share_enclosing_loop_in_events(else_events, source_span, sink_span)
                {
                    return true;
                }
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if spans_share_enclosing_loop_in_events(body, source_span, sink_span) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if spans_share_enclosing_loop_in_events(body, source_span, sink_span)
                    || spans_share_enclosing_loop_in_events(catch_events, source_span, sink_span)
                    || spans_share_enclosing_loop_in_events(finally_events, source_span, sink_span)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// True when the sanitizer's match span overlaps a call recorded
/// by the taint engine as carrying tainted arguments. Without this,
/// any rule whose call site happens to live on the source-to-sink
/// chain would be credited even when its arguments have nothing to
/// do with the tainted value — see WC#4 in the Redis evaluation
/// where a lock-acquire call was being flagged as a wrong-context
/// sanitizer for an unrelated memory sink.
fn sanitizer_call_overlaps_tainted_call(san: &RuleMatch, tainted_call_spans: &AHashSet<Span>) -> bool {
    tainted_call_spans
        .iter()
        .any(|span| spans_overlap(*span, san.span))
}

fn sanitizer_char_allowlist_guards_tainted_call(
    sanitizer_rule: Option<&Rule>,
    san: &RuleMatch,
    tainted_call_spans: &AHashSet<Span>,
) -> bool {
    if sanitizer_rule.and_then(|rule| rule.tag.as_deref()) != Some("char-allowlist") {
        return false;
    }
    tainted_call_spans.iter().any(|span| {
        span.file == san.span.file
            && san.span.end <= span.start
            && span.start.saturating_sub(san.span.end) <= 128
    })
}

/// M4: a sanitizer is only "nested in a tainted sink arg" when the
/// sink arg actually INVOKES the sanitizer as a call AND a tainted
/// carrier sits inside that call's parentheses. The old unanchored
/// `value_text.contains(text)` credited any arg whose text merely
/// contained the callee identifier as a substring (a field, a literal,
/// a longer identifier, or a sibling call), wrongly downgrading real
/// flows to `Sanitized`. The carrier comes from the source match so
/// `escapeHtml("static") + Input` does NOT credit (the tainted `Input`
/// is concatenated OUTSIDE the sanitizer call), while a genuine
/// `["ping ", uri_string:quote(Input)]` still does.
fn sanitizer_is_nested_in_tainted_sink_arg(
    ws: &Workspace,
    sink_func: FuncId,
    src: &RuleMatch,
    san: &RuleMatch,
    snk: &RuleMatch,
    sink_tainted_args: &[TaintedArgInfo],
) -> bool {
    if san.span.file != snk.span.file || sink_tainted_args.is_empty() {
        return false;
    }
    let Some(decl) = ws.exact_decl(SymbolId::new(sink_func.raw())) else {
        return false;
    };
    let Some(FlowEvent::Call {
        span: sink_call_span,
        args: sink_args,
        ..
    }) = find_call_event_at(&decl.flow_events, snk.span)
    else {
        return false;
    };
    let Some(FlowEvent::Call {
        span: sanitizer_call_span,
        name: sanitizer_call_name,
        receiver: sanitizer_receiver,
        args: sanitizer_args,
        ..
    }) = find_call_event_at(&decl.flow_events, san.span)
    else {
        return false;
    };
    if sanitizer_call_span == sink_call_span
        || clean_overwrite_callee_tail(sanitizer_call_name) != clean_overwrite_callee_tail(&san.match_text)
    {
        return false;
    }

    let mut sanitizer_values = call_arg_value_keys(sanitizer_args);
    sanitizer_values.extend(sanitizer_receiver.as_deref().and_then(clean_overwrite_target_key));
    sanitizer_values.extend(
        sanitizer_receiver
            .as_deref()
            .and_then(source_expr_base_identifier)
            .and_then(clean_overwrite_target_key),
    );
    if sanitizer_values.is_empty() {
        return false;
    }
    let source_carrier = source_expr_base_identifier(&src.match_text).and_then(clean_overwrite_target_key);
    sink_tainted_args.iter().any(|tainted| {
        let Some(sink_arg) = sink_args.get(tainted.index) else {
            return false;
        };
        if !span_contains(sink_arg.span, *sanitizer_call_span) {
            return false;
        }
        let sink_values = call_arg_value_keys(std::slice::from_ref(sink_arg));
        let wraps_original_carrier = source_carrier
            .as_ref()
            .is_some_and(|carrier| sanitizer_values.contains(carrier));
        wraps_original_carrier || (!sink_values.is_empty() && sink_values.is_subset(&sanitizer_values))
    })
}

fn call_arg_value_keys(args: &[bonsai_lang_api::CallArg]) -> AHashSet<String> {
    args.iter()
        .flat_map(|arg| {
            arg.source_names
                .iter()
                .map(String::as_str)
                .chain(arg.place.as_deref())
        })
        .filter_map(clean_overwrite_target_key)
        .collect()
}

fn xxe_factory_hardening_sanitizes_sink(
    ws: &Workspace,
    sink_func: FuncId,
    sanitizer_rule: Option<&Rule>,
    sink_rule: &Rule,
    san: &RuleMatch,
    snk: &RuleMatch,
) -> bool {
    if sanitizer_rule.and_then(|rule| rule.tag.as_deref()) != Some("xxe-sanitizer")
        || sink_rule.tag.as_deref() != Some("xxe")
        || san.span.file != snk.span.file
        || !match_precedes_or_same(san, snk)
    {
        return false;
    }
    let Some(factory_receiver) = receiver_text_from_match(&san.match_text) else {
        return false;
    };
    let Some(sink_receiver) = receiver_text_from_match(&snk.match_text) else {
        return false;
    };
    if factory_receiver == sink_receiver {
        return true;
    }
    builder_created_from_factory_before_sink(
        ws,
        sink_func,
        san.span,
        snk.span,
        sink_receiver,
        factory_receiver,
    )
}

fn receiver_text_from_match(text: &str) -> Option<&str> {
    let (receiver, _) = text.trim().rsplit_once('.')?;
    let receiver = receiver.trim();
    (!receiver.is_empty()).then_some(receiver)
}

fn builder_created_from_factory_before_sink(
    ws: &Workspace,
    sink_func: FuncId,
    san_span: Span,
    sink_span: Span,
    builder_receiver: &str,
    factory_receiver: &str,
) -> bool {
    if san_span.file != sink_span.file || san_span.end > sink_span.start {
        return false;
    }
    let Some(decl) = ws.exact_decl(SymbolId::new(sink_func.raw())) else {
        return false;
    };
    builder_available_at_sink(
        &decl.flow_events,
        &decl.flow_events,
        san_span,
        sink_span,
        builder_receiver,
        factory_receiver,
        false,
    )
    .unwrap_or(false)
}

fn builder_available_at_sink(
    events: &[FlowEvent],
    all_events: &[FlowEvent],
    sanitizer_span: Span,
    sink_span: Span,
    builder_receiver: &str,
    factory_receiver: &str,
    mut available: bool,
) -> Option<bool> {
    for event in events {
        match event {
            FlowEvent::Assign { span, target, .. } => {
                if sanitizer_span.end <= span.start
                    && span.end <= sink_span.start
                    && clean_overwrite_target_key(target) == clean_overwrite_target_key(builder_receiver)
                    && assignment_uses_factory_builder(all_events, *span, factory_receiver)
                {
                    available = true;
                }
            }
            FlowEvent::Call { span, .. } if spans_overlap(*span, sink_span) => return Some(available),
            FlowEvent::Branch {
                span,
                then_events,
                else_events,
                ..
            } if span_contains(*span, sink_span) => {
                return builder_available_at_sink(
                    then_events,
                    all_events,
                    sanitizer_span,
                    sink_span,
                    builder_receiver,
                    factory_receiver,
                    available,
                )
                .or_else(|| {
                    builder_available_at_sink(
                        else_events,
                        all_events,
                        sanitizer_span,
                        sink_span,
                        builder_receiver,
                        factory_receiver,
                        available,
                    )
                });
            }
            FlowEvent::Loop { span, body, .. }
            | FlowEvent::Defer { span, body }
            | FlowEvent::Using { span, body, .. }
                if span_contains(*span, sink_span) =>
            {
                return builder_available_at_sink(
                    body,
                    all_events,
                    sanitizer_span,
                    sink_span,
                    builder_receiver,
                    factory_receiver,
                    available,
                );
            }
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                ..
            } if span_contains(*span, sink_span) => {
                return builder_available_at_sink(
                    body,
                    all_events,
                    sanitizer_span,
                    sink_span,
                    builder_receiver,
                    factory_receiver,
                    available,
                )
                .or_else(|| {
                    builder_available_at_sink(
                        catch_events,
                        all_events,
                        sanitizer_span,
                        sink_span,
                        builder_receiver,
                        factory_receiver,
                        available,
                    )
                })
                .or_else(|| {
                    builder_available_at_sink(
                        finally_events,
                        all_events,
                        sanitizer_span,
                        sink_span,
                        builder_receiver,
                        factory_receiver,
                        available,
                    )
                });
            }
            _ => {}
        }
    }
    None
}

fn assignment_uses_factory_builder(
    events: &[FlowEvent],
    assignment_span: Span,
    factory_receiver: &str,
) -> bool {
    for event in events {
        match event {
            FlowEvent::Call {
                span, name, receiver, ..
            } => {
                if (span_contains(assignment_span, *span) || spans_overlap(assignment_span, *span))
                    && clean_overwrite_callee_tail(name) == "newdocumentbuilder"
                    && receiver.as_deref().and_then(clean_overwrite_target_key)
                        == clean_overwrite_target_key(factory_receiver)
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if assignment_uses_factory_builder(then_events, assignment_span, factory_receiver)
                    || assignment_uses_factory_builder(else_events, assignment_span, factory_receiver)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if assignment_uses_factory_builder(body, assignment_span, factory_receiver) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if assignment_uses_factory_builder(body, assignment_span, factory_receiver)
                    || assignment_uses_factory_builder(catch_events, assignment_span, factory_receiver)
                    || assignment_uses_factory_builder(finally_events, assignment_span, factory_receiver)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// True when `token` appears in one adapter-selected expression as a whole
/// identifier. This is used only by the small guard-condition evaluator.
fn text_mentions_token(text: &str, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let bytes = text.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find(token) {
        let start = search_from + rel;
        let end = start + token.len();
        search_from = start + 1;
        let before_ok = start == 0 || {
            let byte = bytes[start - 1];
            !(byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric())
        };
        let after_ok = end >= bytes.len() || {
            let byte = bytes[end];
            !(byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric())
        };
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// True when a sanitizer match could plausibly attach to the
/// source→sink chain — must come AFTER the source within the
/// source's enclosing fn, and BEFORE the sink within the sink's
/// enclosing fn. A sanitizer that wraps the source can have its
/// callee token before the nested source token; source-specific
/// data-flow evidence is enough to accept that case. A sanitizer
/// nested inside a tainted sink argument is semantically before the
/// sink execution even though its callee token appears after the sink
/// callee token. Cross-fn sanitizers always pass this gate; the
/// chain-hop check elsewhere handles inter-fn placement.
// Each argument is a distinct piece of placement context; bundling them
// into a struct would only move the noise.
#[allow(clippy::too_many_arguments)]
fn sanitizer_can_attach(
    src: &RuleMatch,
    source_func: FuncId,
    san: &RuleMatch,
    sanitizer_func: FuncId,
    snk: &RuleMatch,
    sink_func: FuncId,
    nested_in_tainted_sink_arg: bool,
    dataflow_connected: bool,
    post_sink_path_construction_containment: bool,
) -> bool {
    if sanitizer_func == source_func && !match_precedes_or_same(src, san) && !dataflow_connected {
        return false;
    }
    if sanitizer_func == sink_func
        && !match_precedes_or_same(san, snk)
        && !nested_in_tainted_sink_arg
        && !post_sink_path_construction_containment
    {
        return false;
    }
    true
}

fn sanitizer_assignment_output_feeds_sink_arg(
    ws: &Workspace,
    sanitizer_func: FuncId,
    san: &RuleMatch,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> bool {
    if san.span.file != snk.span.file || !match_precedes_or_same(san, snk) {
        return false;
    }
    let target_keys = sanitizer_assignment_sink_target_keys(snk, sink_rule, sink_tainted_args);
    if target_keys.is_empty() {
        return false;
    }
    let Some(decl) = ws.exact_decl(SymbolId::new(sanitizer_func.raw())) else {
        return false;
    };
    sanitizer_assignment_output_feeds_sink_arg_in_events(&decl.flow_events, san, &target_keys)
}

fn sanitizer_assignment_sink_target_keys(
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> AHashSet<String> {
    let mut target_keys: AHashSet<String> = sink_tainted_args
        .iter()
        .flat_map(tainted_arg_target_keys)
        .collect();
    if target_keys.is_empty() && sink_rule.match_spec.kind == MatchKind::Return {
        target_keys.extend(clean_overwrite_target_key(&snk.match_text));
    }
    target_keys
}

fn sanitizer_assignment_output_feeds_sink_arg_in_events(
    events: &[FlowEvent],
    san: &RuleMatch,
    target_keys: &AHashSet<String>,
) -> bool {
    let sanitizer_targets = sanitizer_assignment_targets_in_events(events, san);
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_call,
                source_name,
                source_call_args,
                source_names,
                ..
            } => {
                let Some(target_key) = clean_overwrite_target_key(target) else {
                    continue;
                };
                if !target_keys.contains(&target_key) {
                    continue;
                }
                let direct_sanitizer_assignment = (spans_overlap(*span, san.span)
                    || span_contains(*span, san.span))
                    && source_call.as_deref().is_some_and(|source_call| {
                        security_text_matches_source_strict(source_call, &san.match_text)
                            || security_text_matches_source_strict(&san.match_text, source_call)
                            || spans_overlap(*span, san.span)
                    });
                let assignment_uses_sanitized_local = assignment_sources_include_any(
                    source_name.as_deref(),
                    source_call_args,
                    source_names,
                    &sanitizer_targets,
                );
                if direct_sanitizer_assignment || assignment_uses_sanitized_local {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if sanitizer_assignment_output_feeds_sink_arg_in_events(then_events, san, target_keys)
                    || sanitizer_assignment_output_feeds_sink_arg_in_events(else_events, san, target_keys)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if sanitizer_assignment_output_feeds_sink_arg_in_events(body, san, target_keys) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if sanitizer_assignment_output_feeds_sink_arg_in_events(body, san, target_keys)
                    || sanitizer_assignment_output_feeds_sink_arg_in_events(catch_events, san, target_keys)
                    || sanitizer_assignment_output_feeds_sink_arg_in_events(finally_events, san, target_keys)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn sanitizer_assignment_targets_in_events(events: &[FlowEvent], san: &RuleMatch) -> AHashSet<String> {
    let mut targets = AHashSet::new();
    collect_sanitizer_assignment_targets(events, san, &mut targets);
    targets
}

fn collect_sanitizer_assignment_targets(
    events: &[FlowEvent],
    san: &RuleMatch,
    targets: &mut AHashSet<String>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_call,
                ..
            } => {
                let Some(target_key) = clean_overwrite_target_key(target) else {
                    continue;
                };
                let source_call_matches = source_call.as_deref().is_some_and(|source_call| {
                    security_text_matches_source_strict(source_call, &san.match_text)
                        || security_text_matches_source_strict(&san.match_text, source_call)
                });
                if spans_overlap(*span, san.span) || span_contains(*span, san.span) || source_call_matches {
                    targets.insert(target_key);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_sanitizer_assignment_targets(then_events, san, targets);
                collect_sanitizer_assignment_targets(else_events, san, targets);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_sanitizer_assignment_targets(body, san, targets);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_sanitizer_assignment_targets(body, san, targets);
                collect_sanitizer_assignment_targets(catch_events, san, targets);
                collect_sanitizer_assignment_targets(finally_events, san, targets);
            }
            _ => {}
        }
    }
}

fn assignment_sources_include_any(
    source_name: Option<&str>,
    source_call_args: &[String],
    source_names: &[String],
    candidates: &AHashSet<String>,
) -> bool {
    !candidates.is_empty()
        && source_name
            .into_iter()
            .chain(source_call_args.iter().map(String::as_str))
            .chain(source_names.iter().map(String::as_str))
            .filter_map(clean_overwrite_target_key)
            .any(|source| candidates.contains(&source))
}

struct SanitizerGuardContext<'a> {
    ws: &'a Workspace,
    sink_tainted_args: &'a [TaintedArgInfo],
}

fn sanitizer_guard_feeds_sink_arg(
    context: &SanitizerGuardContext<'_>,
    pack: &Rulepack,
    sanitizer_func: FuncId,
    sanitizer_rule: Option<&Rule>,
    san: &RuleMatch,
    sanitizer_hits: &[&RuleMatch],
    snk: &RuleMatch,
) -> bool {
    let Some(tag) = sanitizer_rule.and_then(|rule| rule.tag.as_deref()) else {
        return false;
    };
    if !matches!(
        tag,
        "same-origin-path" | "ssrf-sanitize" | "allowlist-validate" | "nosql-sanitize"
    ) || san.span.file != snk.span.file
        || !match_precedes_or_same(san, snk)
    {
        return false;
    }
    let target_keys: AHashSet<String> = context
        .sink_tainted_args
        .iter()
        .flat_map(tainted_arg_target_keys)
        .filter(|target| !looks_like_clean_constant(target))
        .collect();
    if target_keys.is_empty() {
        return false;
    }
    let Some(decl) = context.ws.exact_decl(SymbolId::new(sanitizer_func.raw())) else {
        return false;
    };
    if tag == "nosql-sanitize" {
        return terminal_type_guards_cover_sink_targets(
            context.ws,
            &decl,
            sanitizer_rule.expect("tag came from a sanitizer rule"),
            sanitizer_hits,
            snk,
            &target_keys,
        );
    }
    let mut guarded = sanitizer_guard_variables_in_events(&decl.flow_events, san, tag);
    guarded.retain(|var| !looks_like_clean_constant(var));
    if guarded.is_empty() {
        return false;
    }
    let guarded_set: AHashSet<String> = guarded.into_iter().collect();
    if target_keys.iter().any(|target| guarded_set.contains(target)) {
        return true;
    }
    let receiver_mutation_targets = pack.receiver_mutation_targets(&snk.language);
    guarded_variable_feeds_sink_target_in_events(
        &decl.flow_events,
        san.span,
        snk.span,
        &guarded_set,
        &target_keys,
    ) || guarded_variable_flows_into_receiver_before_sink(
        &decl.flow_events,
        san.span,
        snk.span,
        &guarded_set,
        &target_keys,
        receiver_mutation_targets,
    )
}

fn terminal_type_guards_cover_sink_targets(
    ws: &Workspace,
    decl: &bonsai_lang_api::Decl,
    sanitizer_rule: &Rule,
    sanitizer_hits: &[&RuleMatch],
    sink: &RuleMatch,
    sink_targets: &AHashSet<String>,
) -> bool {
    sink_targets.iter().all(|target| {
        sanitizer_hits
            .iter()
            .filter(|candidate| {
                candidate.rule_id == sanitizer_rule.id
                    && candidate.span.file == sink.span.file
                    && match_precedes_or_same(candidate, sink)
            })
            .any(|candidate| {
                let guarded =
                    sanitizer_guard_variables_in_events(&decl.flow_events, candidate, "nosql-sanitize");
                if !guarded.iter().any(|place| place == target) {
                    return false;
                }
                let Some(branch_span) =
                    terminal_rejection_predicate_guard_span(ws, decl, candidate.span, sink.span)
                else {
                    return false;
                };
                !place_is_assigned_between(&decl.flow_events, target, branch_span.end, sink.span.start)
            })
    })
}

fn sanitizer_guard_variables_in_events(events: &[FlowEvent], san: &RuleMatch, tag: &str) -> Vec<String> {
    let mut vars = Vec::new();
    collect_sanitizer_guard_variables(events, san, tag, &mut vars);
    vars.sort();
    vars.dedup();
    vars
}

fn collect_sanitizer_guard_variables(
    events: &[FlowEvent],
    san: &RuleMatch,
    tag: &str,
    vars: &mut Vec<String>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                span, receiver, args, ..
            } if spans_overlap(*span, san.span) || span_contains(*span, san.span) => {
                if matches!(tag, "same-origin-path") {
                    if let Some(receiver) = receiver.as_deref().and_then(clean_overwrite_target_key) {
                        vars.push(receiver);
                    }
                }
                if matches!(tag, "ssrf-sanitize" | "allowlist-validate") {
                    for arg in args {
                        if let Some(place) = arg.place.as_deref().and_then(clean_overwrite_target_key) {
                            vars.push(place);
                        }
                        if let Some(value) = clean_overwrite_target_key(&arg.value_text) {
                            vars.push(value);
                        }
                        for source in &arg.source_names {
                            if let Some(value) = clean_overwrite_target_key(source) {
                                vars.push(value);
                            }
                        }
                    }
                }
                if tag == "nosql-sanitize" {
                    if let Some(arg) = args.first() {
                        if let Some(place) = arg.place.as_deref().and_then(clean_overwrite_target_key) {
                            vars.push(place);
                        }
                        if let Some(value) = clean_overwrite_target_key(&arg.value_text) {
                            vars.push(value);
                        }
                        for source in &arg.source_names {
                            if let Some(value) = clean_overwrite_target_key(source) {
                                vars.push(value);
                            }
                        }
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_sanitizer_guard_variables(then_events, san, tag, vars);
                collect_sanitizer_guard_variables(else_events, san, tag, vars);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_sanitizer_guard_variables(body, san, tag, vars);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_sanitizer_guard_variables(body, san, tag, vars);
                collect_sanitizer_guard_variables(catch_events, san, tag, vars);
                collect_sanitizer_guard_variables(finally_events, san, tag, vars);
            }
            _ => {}
        }
    }
}

fn guarded_variable_feeds_sink_target_in_events(
    events: &[FlowEvent],
    guard_span: Span,
    sink_span: Span,
    guarded: &AHashSet<String>,
    sink_targets: &AHashSet<String>,
) -> bool {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call_args,
                source_names,
                ..
            } if span.file == sink_span.file
                && guard_span.end <= span.start
                && span.start <= sink_span.start =>
            {
                let Some(target_key) = clean_overwrite_target_key(target) else {
                    continue;
                };
                if sink_targets.contains(&target_key)
                    && assignment_sources_include_any(
                        source_name.as_deref(),
                        source_call_args,
                        source_names,
                        guarded,
                    )
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if guarded_variable_feeds_sink_target_in_events(
                    then_events,
                    guard_span,
                    sink_span,
                    guarded,
                    sink_targets,
                ) || guarded_variable_feeds_sink_target_in_events(
                    else_events,
                    guard_span,
                    sink_span,
                    guarded,
                    sink_targets,
                ) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if guarded_variable_feeds_sink_target_in_events(
                    body,
                    guard_span,
                    sink_span,
                    guarded,
                    sink_targets,
                ) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if guarded_variable_feeds_sink_target_in_events(
                    body,
                    guard_span,
                    sink_span,
                    guarded,
                    sink_targets,
                ) || guarded_variable_feeds_sink_target_in_events(
                    catch_events,
                    guard_span,
                    sink_span,
                    guarded,
                    sink_targets,
                ) || guarded_variable_feeds_sink_target_in_events(
                    finally_events,
                    guard_span,
                    sink_span,
                    guarded,
                    sink_targets,
                ) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn guarded_variable_flows_into_receiver_before_sink(
    events: &[FlowEvent],
    guard_span: Span,
    sink_span: Span,
    guarded: &AHashSet<String>,
    receiver_targets: &AHashSet<String>,
    receiver_mutation_targets: &[RuleTarget],
) -> bool {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types,
                args,
                ..
            } if span.file == sink_span.file
                && guard_span.end <= span.start
                && span.start <= sink_span.start =>
            {
                let Some(receiver) = receiver.as_deref().and_then(clean_overwrite_target_key) else {
                    continue;
                };
                if !receiver_targets.contains(&receiver)
                    || !receiver_mutation_targets
                        .iter()
                        .any(|target| rule_target_matches_call(name, receiver_types, target))
                {
                    continue;
                }
                if args.iter().any(|arg| {
                    call_arg_target_keys(arg)
                        .into_iter()
                        .any(|key| guarded.contains(&key))
                }) {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if guarded_variable_flows_into_receiver_before_sink(
                    then_events,
                    guard_span,
                    sink_span,
                    guarded,
                    receiver_targets,
                    receiver_mutation_targets,
                ) || guarded_variable_flows_into_receiver_before_sink(
                    else_events,
                    guard_span,
                    sink_span,
                    guarded,
                    receiver_targets,
                    receiver_mutation_targets,
                ) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if guarded_variable_flows_into_receiver_before_sink(
                    body,
                    guard_span,
                    sink_span,
                    guarded,
                    receiver_targets,
                    receiver_mutation_targets,
                ) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if guarded_variable_flows_into_receiver_before_sink(
                    body,
                    guard_span,
                    sink_span,
                    guarded,
                    receiver_targets,
                    receiver_mutation_targets,
                ) || guarded_variable_flows_into_receiver_before_sink(
                    catch_events,
                    guard_span,
                    sink_span,
                    guarded,
                    receiver_targets,
                    receiver_mutation_targets,
                ) || guarded_variable_flows_into_receiver_before_sink(
                    finally_events,
                    guard_span,
                    sink_span,
                    guarded,
                    receiver_targets,
                    receiver_mutation_targets,
                ) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn post_sink_path_construction_containment_allowed(
    sanitizer_rule: Option<&Rule>,
    sink_rule: &Rule,
    san: &RuleMatch,
    snk: &RuleMatch,
) -> bool {
    if sanitizer_rule.and_then(|rule| rule.tag.as_deref()) != Some("path-sanitize")
        || sink_rule.tag.as_deref() != Some("path-traversal")
        || san.span.file != snk.span.file
        || match_precedes_or_same(san, snk)
    {
        return false;
    }
    sink_rule
        .analysis_semantics
        .as_ref()
        .and_then(|semantics| semantics.post_sink_policy)
        == Some(PostSinkPolicy::PathConstructionContainment)
}

/// True when match `a` is at the same position as or before match
/// `b` (line-then-column comparison).
fn match_precedes_or_same(a: &RuleMatch, b: &RuleMatch) -> bool {
    a.line < b.line || (a.line == b.line && a.column <= b.column)
}

fn tainted_call_matches_sink(call: &TaintedCall, sink: &RuleMatch) -> bool {
    // Span equality is the semantic gate: the matcher already located
    // the sink at this exact program point, and the taint engine
    // already proved the call there carries tainted args. Anything
    // beyond that — text comparison of callee names, tail matching,
    // sink-text candidate expansion — is a heuristic that could
    // attach the same taint evidence to UNRELATED callees that
    // happen to share a method name. See
    // `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
    spans_overlap(call.call_span, sink.span)
}

/// Normalize one adapter-selected compiler fact for small static evaluators.
/// Callers pass branch conditions, arguments, or assignment renderings—not
/// an enclosing source region.
fn compact_guard_text(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}

/// True iff `rule_id` resolves to a rule whose match kind binds to
/// the declaration site itself (`kind: param`) rather than a call /
/// read / write expression. The IDG seeding falls back from
/// span-anchored to param-based for these rules — anchoring at a
/// `kind: param` span is meaningless because the match span is the
/// parameter identifier in the function signature, not an
/// expression with associated IDG nodes.
fn rule_match_kind_is_param(pack: &Rulepack, rule_id: &str) -> bool {
    pack.find_rule_by_id(rule_id)
        .map(|r| matches!(r.match_spec.kind, crate::rule::MatchKind::Param))
        .unwrap_or(false)
}

fn source_anchor_for_rule_match(pack: &Rulepack, src: &RuleMatch) -> Option<Span> {
    if src.origin != MatchOrigin::Rulepack || rule_match_kind_is_param(pack, &src.rule_id) {
        None
    } else {
        Some(src.span)
    }
}

/// Resolve the source rule's `source_output_args` indices to the
/// concrete carrier names at the source's call site. The IDG seeder
/// then includes post-call reads/writes of those carriers so the
/// side-effect taint flows into downstream consumers.
fn find_call_event_at(events: &[FlowEvent], target: bonsai_common::Span) -> Option<&FlowEvent> {
    fn rank(span: Span, target: Span) -> Option<(u8, u64, u64)> {
        if span.file != target.file {
            return None;
        }
        if span == target {
            return Some((0, 0, 0));
        }
        if span_contains(span, target) {
            // The innermost containing call is the AST event that owns a
            // nested source match; outer calls must not steal its arguments.
            return Some((1, span.len(), 0));
        }
        if spans_overlap(span, target) {
            let overlap_start = span.start.max(target.start);
            let overlap_end = span.end.min(target.end);
            let overlap = overlap_end.saturating_sub(overlap_start);
            return Some((2, u64::MAX.saturating_sub(overlap), span.len()));
        }
        None
    }

    fn collect_best<'a>(
        events: &'a [FlowEvent],
        target: Span,
        best: &mut Option<((u8, u64, u64), &'a FlowEvent)>,
    ) {
        for event in events {
            if let FlowEvent::Call { span, .. } = event {
                if let Some(candidate_rank) = rank(*span, target) {
                    if best
                        .as_ref()
                        .is_none_or(|(best_rank, _)| candidate_rank < *best_rank)
                    {
                        *best = Some((candidate_rank, event));
                    }
                }
            }
            match event {
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    collect_best(then_events, target, best);
                    collect_best(else_events, target, best);
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    collect_best(body, target, best);
                    collect_best(catch_events, target, best);
                    collect_best(finally_events, target, best);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => collect_best(body, target, best),
                _ => {}
            }
        }
    }

    let mut best = None;
    collect_best(events, target, &mut best);
    best.map(|(_, event)| event)
}

fn output_arg_names_for_match(pack: &Rulepack, src: &RuleMatch, decl: &bonsai_lang_api::Decl) -> Vec<String> {
    let Some(rule) = pack.find_rule_by_id(&src.rule_id) else {
        return Vec::new();
    };
    let Some(semantics) = rule.taint_semantics.as_ref() else {
        return Vec::new();
    };
    if semantics.source_output_args.is_empty() {
        return Vec::new();
    }
    let Some(FlowEvent::Call { args, .. }) = find_call_event_at(&decl.flow_events, src.span) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for &idx in &semantics.source_output_args {
        let Some(arg) = args.get(idx) else { continue };
        if let Some(name) = arg.place.as_deref() {
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
        for n in &arg.source_names {
            if !n.is_empty() {
                out.push(n.clone());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn source_seed_set(pack: &Rulepack, src: &RuleMatch, decl: &bonsai_lang_api::Decl) -> TokenSet {
    let mut out = TokenSet::default();
    let is_inferred = src.origin != MatchOrigin::Rulepack;
    let rule = pack.find_rule_by_id(&src.rule_id);
    let is_param_rule = rule.is_some_and(|rule| rule.match_spec.kind == MatchKind::Param);
    let source_output_args = rule
        .and_then(|rule| rule.taint_semantics.as_ref())
        .map(|semantics| semantics.source_output_args.as_slice())
        .unwrap_or(&[]);
    let source_callback_args = rule
        .and_then(|rule| rule.taint_semantics.as_ref())
        .map(|semantics| semantics.source_callback_args.as_slice())
        .unwrap_or(&[]);
    if is_inferred || is_param_rule {
        insert_taint_aliases(&mut out, &src.match_text);
        insert_descendant_taint_aliases(&mut out, &src.match_text);
    }
    let allow_text_only_source_match = is_inferred || is_param_rule;
    collect_source_seed_targets(
        &decl.flow_events,
        src,
        source_output_args,
        source_callback_args,
        allow_text_only_source_match,
        &mut out,
    );
    if out.is_empty() && (is_inferred || is_param_rule) {
        insert_taint_aliases(&mut out, &src.match_text);
    }
    out
}

/// True when `inner` is fully contained within `outer` (same file,
/// inclusive byte range).
fn span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
}

/// True when two spans share at least one byte. File ids must match —
/// cross-file spans never overlap even if their byte ranges happen
/// to coincide.
fn spans_overlap(a: Span, b: Span) -> bool {
    a.file == b.file && a.start < b.end && b.start < a.end
}

/// One-tier demotion. `Critical → High`, `High → Medium`,
/// `Medium → Low`, `Low → Low`. Used by trust-aware severity
/// adjustment so local-trust sources don't keep network-grade
/// `high` severity.
fn demote_severity_one_tier(sev: Severity) -> Severity {
    match sev {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low | Severity::Info => Severity::Info,
    }
}

fn source_sink_flow_emission_key(
    idx: usize,
    snk: &RuleMatch,
    call: &TaintedCall,
) -> (usize, String, u32, u64, u64, Option<u64>) {
    (
        idx,
        snk.rule_id.clone(),
        snk.span.file.raw(),
        snk.span.start,
        snk.span.end,
        call.parent_trace_id,
    )
}

/// Stable label for a `Precision` value. Used in the rendered finding
/// (`precision: exact` / `narrowed` / `over-approximate` /
/// `unknown`).
fn precision_label(precision: Precision) -> &'static str {
    match precision {
        Precision::Exact => "exact",
        Precision::Narrowed => "narrowed",
        Precision::OverApproximate => "over-approximate",
        Precision::Unknown => "unknown",
    }
}

fn static_evidence_label(max_precision: Option<Precision>) -> &'static str {
    match max_precision {
        Some(Precision::Exact) => "exact",
        _ => "exact+narrowed",
    }
}

fn precision_from_label(label: &str) -> Option<Precision> {
    match label {
        "exact" => Some(Precision::Exact),
        "narrowed" => Some(Precision::Narrowed),
        "over-approximate" | "over_approximate" => Some(Precision::OverApproximate),
        "unknown" => Some(Precision::Unknown),
        _ => None,
    }
}

fn finding_precision_within(label: &str, max_precision: Precision) -> bool {
    precision_from_label(label)
        .is_some_and(|precision| precision.is_proven_static_evidence() && precision <= max_precision)
}

fn flow_id_for_taint_path(chain_names: &[String], taint_path: &[TaintPropagationStep]) -> String {
    let tokens = taint_path_identity_tokens(chain_names, taint_path);
    bonsai_inspect::compute_flow_id(&tokens)
}

#[cfg(test)]
fn flow_id_for_chain_names(chain_names: &[String]) -> String {
    bonsai_inspect::compute_flow_id(chain_names)
}

fn group_id_for_taint_path(chain_names: &[String], taint_path: &[TaintPropagationStep]) -> String {
    let tokens = taint_path_identity_tokens(chain_names, taint_path);
    if tokens.len() > 1 {
        bonsai_inspect::compute_group_id(&tokens[1..])
    } else {
        bonsai_inspect::compute_group_id(&tokens)
    }
}

#[cfg(test)]
fn group_id_for_chain_names(chain_names: &[String]) -> String {
    bonsai_inspect::compute_group_id(group_tail_for_chain_names(chain_names))
}

#[cfg(test)]
fn group_tail_for_chain_names(chain_names: &[String]) -> &[String] {
    if chain_names.len() > 1 {
        &chain_names[1..]
    } else {
        chain_names
    }
}

fn taint_path_identity_tokens(chain_names: &[String], taint_path: &[TaintPropagationStep]) -> Vec<String> {
    if taint_path.is_empty() {
        return chain_names.to_vec();
    }
    let mut tokens = Vec::new();
    for step in taint_path {
        tokens.push(format!(
            "{}\0{}\0{}:{}:{}",
            step.caller, step.callee, step.file, step.line, step.column
        ));
        for arg in &step.tainted_args {
            tokens.push(format!(
                "arg:{}\0{}\0{}",
                arg.index, arg.value_text, arg.param_name
            ));
        }
    }
    tokens
}

/// Decide the finding status from the sanitizers observed on the
/// chain. Pure function over the sanitizer-tag → sink-tag credit
/// table — see [`sanitizer_credits_sink_tag`].
///
/// Three branches:
/// - **Sanitized**: any sanitizer in the chain credits the sink
///   tag (same-tag credit OR cross-tag entry in `MAPPING`).
/// - **WrongContext**: at least one sanitizer in the chain has a
///   real credit-bearing tag but none credit THIS sink — the
///   developer attempted to filter for a different sink family.
/// - **Unsanitized**: every sanitizer in the chain is either
///   recognised non-crediting (passthrough/validation/hash/etc.)
///   or untagged. No claim was made, so the value reaches the
///   sink unfiltered.
///
/// Untagged sanitizers (`tag.is_none()`) are treated as "no
/// claim" — they neither credit the sink nor push the status to
/// WrongContext. A future change here would silently re-introduce
/// the pre-fix behaviour, so be deliberate.
fn compute_status(sanitizers: &[FindingMatch], sink_tag: Option<&str>) -> FindingStatus {
    if sanitizers.is_empty() {
        return FindingStatus::Unsanitized;
    }
    let mut any_credit = false;
    let mut any_real_sanitizer_fired = false;
    for sanitizer in sanitizers {
        if sanitizer_credits_sink_tag(sanitizer.tag.as_deref(), sink_tag) {
            any_credit = true;
            break;
        }
        // Passthrough markers and inventory-only tags (`validation`,
        // `schema-validate`, `hash`, `url-decode`, `base64-encode`,
        // `non-sanitizer`, `passthrough-*`) make no claim of clearing
        // taint for any sink class. They should NOT push status to
        // WrongContext — that label is reserved for sanitizers that
        // tried to filter for the wrong sink family.
        if let Some(tag) = sanitizer.tag.as_deref() {
            if !sanitizer_tag_is_recognized_non_crediting(tag) {
                any_real_sanitizer_fired = true;
            }
        }
    }
    if any_credit {
        FindingStatus::Sanitized
    } else if any_real_sanitizer_fired {
        FindingStatus::WrongContext
    } else {
        FindingStatus::Unsanitized
    }
}

/// Singular noun label for a rule kind. Plural forms (`sources`,
/// `sinks`, `sanitizers`) live on `RuleKind::dir_name`.
fn rule_kind_str(kind: RuleKind) -> &'static str {
    match kind {
        RuleKind::Source => "source",
        RuleKind::Sink => "sink",
        RuleKind::Sanitizer => "sanitizer",
        RuleKind::Typing => "typing",
    }
}

/// Extract the canonical family segment from a rule id of the shape
/// `<lang>.<family>.<name>`. `python.cmdi.os_system` → `cmdi`,
/// `python.deser.pickle_loads` → `deser`. Falls back to the first
/// non-language segment, then to `id`. The result is run through
/// [`normalise_family`] so callers (audit, JSON, CLI) all key on the
/// same canonical string set as `CANONICAL_SINK_FAMILIES`.
#[must_use]
pub fn rule_family(id: &str) -> &str {
    let mut it = id.splitn(3, '.');
    let _lang = it.next();
    match (it.next(), it.next()) {
        (Some(fam), _) => normalise_family(fam),
        _ => id,
    }
}

/// True when a rule matches a `--category` filter. Accepts:
///   - exact match against the rule's tag (e.g. `command-injection`),
///   - exact match against the canonical family
///     (`rule_family(id)` runs `normalise_family`, so
///     `--category deserialization` matches `python.deser.*`),
///   - exact match against the raw family abbreviation
///     (`--category deser` ALSO matches `python.deser.*` so the
///     short form documented in `args.rs` keeps working). Used by
///     `select_pack_rules`, `sink_inventory`, `sanitizer_inventory`.
#[must_use]
fn rule_matches_category(rule: &Rule, category: &str) -> bool {
    if rule.tag.as_deref() == Some(category) {
        return true;
    }
    if rule_family(&rule.id) == category {
        return true;
    }
    // Raw (pre-normalised) family segment match. We re-split rather
    // than expose a public helper because callers should keep
    // routing through `rule_family` for canonical-only comparisons.
    let raw_family = {
        let mut it = rule.id.splitn(3, '.');
        let _lang = it.next();
        it.next()
    };
    raw_family == Some(category)
}

fn clean_output_overwrites_from_rulepack_for_languages(
    pack: &Rulepack,
    languages: &AHashSet<String>,
) -> Vec<CleanOutputOverwrite> {
    let mut out: Vec<_> = pack
        .all_rules()
        .into_iter()
        .filter(|rule| {
            rule.enabled && rule.kind == RuleKind::Sanitizer && languages.contains(rule.language.as_str())
        })
        .filter_map(|rule| {
            let semantics = rule.taint_semantics.as_ref()?.clean_output_overwrite.as_ref()?;
            let callee = rule
                .match_spec
                .callee
                .as_ref()
                .and_then(semantic_transfer_callee)?;
            Some(CleanOutputOverwrite {
                callee,
                output_arg_index: semantics.output_arg_index,
                value_start_arg_index: semantics.value_start_arg_index,
            })
        })
        .collect();
    sort_clean_output_overwrites(&mut out);
    out
}

fn idg_transfer_options_from_rulepack_shapes(
    overwrites: &[CleanOutputOverwrite],
    source_outputs: &[SourceOutputArgs],
    source_callbacks: &[SourceCallbackArgs],
    output_arg_flows: &[OutputArgFlow],
    receiver_state_propagations: &[ReceiverStatePropagation],
) -> bonsai_idg::TransferOptions {
    bonsai_idg::TransferOptions {
        clean_output_overwrites: overwrites
            .iter()
            .map(|shape| bonsai_idg::CleanOutputOverwriteSpec {
                callee: shape.callee.clone(),
                output_arg_index: shape.output_arg_index,
                value_start_arg_index: shape.value_start_arg_index,
            })
            .collect(),
        source_output_args: source_outputs
            .iter()
            .map(|shape| bonsai_idg::SourceOutputArgSpec {
                callee: shape.callee.clone(),
                output_arg_indices: shape.output_arg_indices.clone(),
            })
            .collect(),
        source_callback_args: source_callbacks
            .iter()
            .map(|shape| bonsai_idg::SourceCallbackArgSpec {
                callee: shape.callee.clone(),
                callback_arg_index: shape.callback_arg_index,
                source_param_indices: shape.source_param_indices.clone(),
            })
            .collect(),
        call_result_passthroughs: Vec::new(),
        output_arg_flows: output_arg_flows
            .iter()
            .map(|shape| bonsai_idg::OutputArgFlowSpec {
                callee: shape.callee.clone(),
                output_arg_index: shape.output_arg_index,
                value_arg_indices: shape.value_arg_indices.clone(),
                value_start_arg_index: shape.value_start_arg_index,
            })
            .collect(),
        receiver_state_propagations: receiver_state_propagations
            .iter()
            .map(|shape| bonsai_idg::ReceiverStatePropagationSpec {
                method: shape.method.clone(),
                receiver_type: shape.receiver_type.clone(),
            })
            .collect(),
        include_diagnostic_field_flows: false,
        include_receiver_method_propagation: false,
        include_field_argument_forwarding: true,
        symbolic_field_forwarding: false,
        symbolic_field_languages: Vec::new(),
        // When no workspace body resolves, AST arguments are the available
        // dependency evidence for the result. Preserve them at narrowed
        // precision, independent of API names; receiver-state mutation still
        // requires a resolved body or declarative external summary.
        include_unresolved_call_result_passthrough: true,
        include_unresolved_receiver_result_passthrough: false,
    }
}

#[derive(Clone, Debug, Default)]
pub struct RulepackTaintTransfers {
    pub receiver_state_propagations: Vec<ReceiverStatePropagation>,
    pub call_result_passthroughs: Vec<CallResultPassthrough>,
    pub output_arg_flows: Vec<OutputArgFlow>,
}

pub fn taint_transfers_from_rulepack(pack: &Rulepack) -> RulepackTaintTransfers {
    RulepackTaintTransfers {
        receiver_state_propagations: receiver_state_propagations_from_rulepack(pack),
        call_result_passthroughs: call_result_passthroughs_from_rulepack(pack),
        output_arg_flows: output_arg_flows_from_rulepack(pack),
    }
}

pub fn seed_idg_service_for_rulepack(ws: &Workspace, pack: &Rulepack) -> Arc<bonsai_idg::IdgQueryService> {
    let languages = workspace_languages(ws);
    let overwrites = clean_output_overwrites_from_rulepack_for_languages(pack, &languages);
    let source_outputs = source_output_args_from_rulepack_for_languages(pack, &languages);
    let source_callbacks = source_callback_args_from_rulepack_for_languages(pack, &languages);
    let output_arg_flows = output_arg_flows_from_rulepack_for_languages(pack, &languages);
    let receiver_state_propagations =
        receiver_state_propagations_from_rulepack_for_languages(pack, &languages);
    let mut options = idg_transfer_options_from_rulepack_shapes(
        &overwrites,
        &source_outputs,
        &source_callbacks,
        &output_arg_flows,
        &receiver_state_propagations,
    );
    options.call_result_passthroughs = idg_call_result_passthrough_specs(
        &call_result_passthroughs_from_rulepack_for_languages(pack, &languages),
    );
    options.symbolic_field_languages = ws.db().complete_field_place_languages();
    options.symbolic_field_forwarding = !options.symbolic_field_languages.is_empty();
    ws.build_and_seed_idg_service_with_transfer_options(&options)
}

fn seed_idg_service_for_rulepack_for_files(
    ws: &Workspace,
    pack: &Rulepack,
    languages: &AHashSet<String>,
    included_files: &[FileId],
    included_funcs: &[FuncId],
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
) -> Arc<bonsai_idg::IdgQueryService> {
    let overwrites = clean_output_overwrites_from_rulepack_for_languages(pack, languages);
    let source_outputs = source_output_args_from_rulepack_for_languages(pack, languages);
    let source_callbacks = source_callback_args_from_rulepack_for_languages(pack, languages);
    let output_arg_flows = output_arg_flows_from_rulepack_for_languages(pack, languages);
    let receiver_state_propagations =
        receiver_state_propagations_from_rulepack_for_languages(pack, languages);
    let mut options = idg_transfer_options_from_rulepack_shapes(
        &overwrites,
        &source_outputs,
        &source_callbacks,
        &output_arg_flows,
        &receiver_state_propagations,
    );
    options.call_result_passthroughs = idg_call_result_passthrough_specs(
        &call_result_passthroughs_from_rulepack_for_languages(pack, languages),
    );
    options.symbolic_field_languages = symbolic_field_languages(ws, included_files);
    options.symbolic_field_forwarding = !options.symbolic_field_languages.is_empty();
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "semantic graph transfer options languages={} funcs={} receiver_method_propagation={} field_argument_forwarding={} symbolic_field_languages={}",
        languages.len(),
        included_funcs.len(),
        options.include_receiver_method_propagation,
        options.include_field_argument_forwarding,
        options.symbolic_field_languages.len()
    );
    ws.build_and_seed_persisted_idg_service_with_transfer_options_for_files_and_call_graph(
        &options,
        included_files,
        included_funcs,
        call_graph,
    )
}

fn symbolic_field_languages(ws: &Workspace, files: &[FileId]) -> Vec<String> {
    let mut languages: Vec<String> = files
        .iter()
        .filter_map(|file| ws.db().adapter_for(*file))
        .filter(|adapter| adapter.capabilities().field_places_complete)
        .map(|adapter| adapter.language_id().as_str().to_string())
        .collect();
    languages.sort();
    languages.dedup();
    languages
}

fn source_output_args_from_rulepack_for_languages(
    pack: &Rulepack,
    languages: &AHashSet<String>,
) -> Vec<SourceOutputArgs> {
    let mut out: Vec<_> = pack
        .all_rules()
        .into_iter()
        .filter(|rule| {
            rule.enabled && rule.kind == RuleKind::Source && languages.contains(rule.language.as_str())
        })
        .filter_map(|rule| {
            let semantics = rule.taint_semantics.as_ref()?;
            if semantics.source_output_args.is_empty() {
                return None;
            }
            let callee = rule
                .match_spec
                .callee
                .as_ref()
                .and_then(semantic_transfer_callee)?;
            let mut output_arg_indices = semantics.source_output_args.clone();
            output_arg_indices.sort_unstable();
            output_arg_indices.dedup();
            Some(SourceOutputArgs {
                callee,
                output_arg_indices,
            })
        })
        .collect();
    sort_source_output_args(&mut out);
    out
}

fn source_callback_args_from_rulepack_for_languages(
    pack: &Rulepack,
    languages: &AHashSet<String>,
) -> Vec<SourceCallbackArgs> {
    let mut out = Vec::new();
    for rule in pack.all_rules() {
        if !rule.enabled || rule.kind != RuleKind::Source || !languages.contains(rule.language.as_str()) {
            continue;
        }
        let Some(semantics) = rule.taint_semantics.as_ref() else {
            continue;
        };
        if semantics.source_callback_args.is_empty() {
            continue;
        }
        let Some(callee) = rule.match_spec.callee.as_ref().and_then(semantic_transfer_callee) else {
            continue;
        };
        for callback in &semantics.source_callback_args {
            let mut source_param_indices = callback.source_param_indices.clone();
            source_param_indices.sort_unstable();
            source_param_indices.dedup();
            out.push(SourceCallbackArgs {
                callee: callee.clone(),
                callback_arg_index: callback.callback_arg_index,
                source_param_indices,
            });
        }
    }
    sort_source_callback_args(&mut out);
    out
}

fn call_result_passthroughs_from_rulepack(pack: &Rulepack) -> Vec<CallResultPassthrough> {
    call_result_passthroughs_from_rules(pack.all_rules())
}

fn call_result_passthroughs_from_rulepack_for_languages(
    pack: &Rulepack,
    languages: &AHashSet<String>,
) -> Vec<CallResultPassthrough> {
    call_result_passthroughs_from_rules(
        pack.all_rules()
            .into_iter()
            .filter(|rule| languages.contains(rule.language.as_str())),
    )
}

fn call_result_passthroughs_from_rules<'a>(
    rules: impl IntoIterator<Item = &'a Rule>,
) -> Vec<CallResultPassthrough> {
    let mut out: Vec<_> = rules
        .into_iter()
        .filter(|rule| rule.enabled && matches!(rule.kind, RuleKind::Sanitizer | RuleKind::Typing))
        .filter_map(|rule| {
            let semantics = rule.taint_semantics.as_ref()?;
            if semantics.call_result_passthrough_args.is_empty()
                && !semantics.call_result_passthrough_receiver
            {
                return None;
            }
            let target = rule.match_spec.callee.as_ref()?;
            let (callee, receiver_type) = if rule.kind == RuleKind::Typing {
                if let Some(attribute) = target.attribute.as_ref().filter(|parts| parts.len() >= 2) {
                    (
                        attribute.last()?.clone(),
                        Some(attribute[..attribute.len() - 1].join(".")),
                    )
                } else {
                    (semantic_transfer_callee(target)?, None)
                }
            } else {
                (semantic_transfer_callee(target)?, None)
            };
            let mut input_arg_indices = semantics.call_result_passthrough_args.clone();
            input_arg_indices.sort_unstable();
            input_arg_indices.dedup();
            Some(CallResultPassthrough {
                callee,
                receiver_type,
                input_arg_indices,
                input_receiver: semantics.call_result_passthrough_receiver,
            })
        })
        .collect();
    sort_call_result_passthroughs(&mut out);
    out
}

fn idg_call_result_passthrough_specs(
    passthroughs: &[CallResultPassthrough],
) -> Vec<bonsai_idg::CallResultPassthroughSpec> {
    passthroughs
        .iter()
        .map(|passthrough| bonsai_idg::CallResultPassthroughSpec {
            callee: passthrough.callee.clone(),
            receiver_type: passthrough.receiver_type.clone(),
            input_arg_indices: passthrough.input_arg_indices.clone(),
            input_receiver: passthrough.input_receiver,
        })
        .collect()
}

fn output_arg_flows_from_rulepack(pack: &Rulepack) -> Vec<OutputArgFlow> {
    output_arg_flows_from_rules(pack.all_rules())
}

fn output_arg_flows_from_rulepack_for_languages(
    pack: &Rulepack,
    languages: &AHashSet<String>,
) -> Vec<OutputArgFlow> {
    output_arg_flows_from_rules(
        pack.all_rules()
            .into_iter()
            .filter(|rule| languages.contains(rule.language.as_str())),
    )
}

fn output_arg_flows_from_rules<'a>(rules: impl IntoIterator<Item = &'a Rule>) -> Vec<OutputArgFlow> {
    let mut out: Vec<_> = rules
        .into_iter()
        .filter(|rule| rule.enabled)
        .flat_map(|rule| {
            let callee = rule.match_spec.callee.as_ref().and_then(semantic_transfer_callee);
            let Some(callee) = callee else {
                return Vec::new();
            };
            rule.taint_semantics
                .as_ref()
                .map(|semantics| {
                    semantics
                        .output_arg_flows
                        .iter()
                        .map(|flow| OutputArgFlow {
                            callee: callee.clone(),
                            output_arg_index: flow.output_arg_index,
                            value_start_arg_index: flow.value_start_arg_index,
                            value_arg_indices: {
                                let mut indices = flow.value_arg_indices.clone();
                                indices.sort_unstable();
                                indices.dedup();
                                indices
                            },
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .collect();
    sort_output_arg_flows(&mut out);
    out
}

fn semantic_transfer_callee(target: &RuleTarget) -> Option<String> {
    target
        .name
        .clone()
        .or_else(|| target.attribute.as_ref().map(|parts| parts.join(".")))
        .or_else(|| target.regex.as_ref().map(|regex| format!("regex:{regex}")))
}

fn receiver_state_propagations_from_rulepack(pack: &Rulepack) -> Vec<ReceiverStatePropagation> {
    receiver_state_propagations_from_rules(pack.all_rules())
}

fn receiver_state_propagations_from_rulepack_for_languages(
    pack: &Rulepack,
    languages: &AHashSet<String>,
) -> Vec<ReceiverStatePropagation> {
    receiver_state_propagations_from_rules(
        pack.all_rules()
            .into_iter()
            .filter(|rule| languages.contains(rule.language.as_str())),
    )
}

fn receiver_state_propagations_from_rules<'a>(
    rules: impl IntoIterator<Item = &'a Rule>,
) -> Vec<ReceiverStatePropagation> {
    let mut out: Vec<_> = rules
        .into_iter()
        .filter(|rule| {
            rule.enabled
                && matches!(rule.kind, RuleKind::Sink | RuleKind::Typing)
                && (rule.kind == RuleKind::Typing || rule_has_taint_predicate(rule))
                && rule
                    .taint_semantics
                    .as_ref()
                    .is_some_and(|semantics| semantics.taint_receiver_from_args)
        })
        .filter_map(receiver_state_propagation_from_rule)
        .collect();
    sort_receiver_state_propagations(&mut out);
    out
}

fn sort_clean_output_overwrites(items: &mut Vec<CleanOutputOverwrite>) {
    items.sort_by(|a, b| {
        (&a.callee, a.output_arg_index, a.value_start_arg_index).cmp(&(
            &b.callee,
            b.output_arg_index,
            b.value_start_arg_index,
        ))
    });
    items.dedup();
}

fn sort_source_output_args(items: &mut Vec<SourceOutputArgs>) {
    items.sort_by(|a, b| (&a.callee, &a.output_arg_indices).cmp(&(&b.callee, &b.output_arg_indices)));
    items.dedup();
}

fn sort_source_callback_args(items: &mut Vec<SourceCallbackArgs>) {
    items.sort_by(|a, b| {
        (&a.callee, a.callback_arg_index, &a.source_param_indices).cmp(&(
            &b.callee,
            b.callback_arg_index,
            &b.source_param_indices,
        ))
    });
    items.dedup();
}

fn sort_call_result_passthroughs(items: &mut Vec<CallResultPassthrough>) {
    items.sort_by(|a, b| {
        (
            &a.callee,
            &a.receiver_type,
            &a.input_arg_indices,
            a.input_receiver,
        )
            .cmp(&(
                &b.callee,
                &b.receiver_type,
                &b.input_arg_indices,
                b.input_receiver,
            ))
    });
    items.dedup();
}

fn sort_output_arg_flows(items: &mut Vec<OutputArgFlow>) {
    items.sort_by(|a, b| {
        (
            &a.callee,
            a.output_arg_index,
            a.value_start_arg_index,
            &a.value_arg_indices,
        )
            .cmp(&(
                &b.callee,
                b.output_arg_index,
                b.value_start_arg_index,
                &b.value_arg_indices,
            ))
    });
    items.dedup();
}

fn sort_receiver_state_propagations(items: &mut Vec<ReceiverStatePropagation>) {
    items.sort_by(|a, b| (&a.method, &a.receiver_type).cmp(&(&b.method, &b.receiver_type)));
    items.dedup();
}

fn receiver_state_propagation_from_rule(rule: &Rule) -> Option<ReceiverStatePropagation> {
    let target = rule.match_spec.callee.as_ref()?;
    let attribute = target.attribute.as_ref()?;
    if attribute.len() < 2 {
        return None;
    }
    let method = attribute.last()?.trim();
    if method.is_empty() {
        return None;
    }
    Some(ReceiverStatePropagation {
        method: method.to_string(),
        receiver_type: Some(attribute[..attribute.len() - 1].join(".")),
    })
}

/// Map common per-language family abbreviations to their canonical
/// name (matches [`CANONICAL_SINK_FAMILIES`]). Only sink-side
/// abbreviations belong here — sanitizer-only families like CSRF
/// (which is the *protection* surface, not a sink class) must NOT
/// be remapped, since doing so would funnel sink rules with a
/// `.csrf.` segment into a non-canonical bucket and silently drop
/// them from `pack_audit`.
#[must_use]
pub fn normalise_family(fam: &str) -> &str {
    match fam {
        "deser" => "deserialization",
        "ssti" => "template",
        "code" => "eval",
        "header" | "host_header" => "header_injection",
        "file" | "path_traversal" => "path",
        "open" => "open_redirect",
        "upload" => "file_upload",
        legacy if legacy.starts_with("upload_") => "file_upload",
        other => other,
    }
}

pub fn select_pack_rules<'a>(pack: &'a Rulepack, options: &PackInventoryOptions) -> Vec<&'a Rule> {
    let mut rules: Vec<&Rule> = pack
        .all_rules()
        .into_iter()
        .filter(|rule| options.lang.as_deref().is_none_or(|lang| rule.language == lang))
        .filter(|rule| options.kind.is_none_or(|kind| rule.kind == kind))
        .filter(|rule| {
            options
                .severity
                .is_none_or(|min| rule.severity.is_some_and(|severity| severity >= min))
        })
        .filter(|rule| {
            options
                .category
                .as_deref()
                .is_none_or(|category| rule_matches_category(rule, category))
        })
        .collect();
    rules.sort_by(|a, b| {
        (a.language.as_str(), a.kind, rule_family(&a.id), a.id.as_str()).cmp(&(
            b.language.as_str(),
            b.kind,
            rule_family(&b.id),
            b.id.as_str(),
        ))
    });
    rules
}

pub fn canonical_sink_audit_applies(lang: &str) -> bool {
    !ECOSYSTEM_SPECIFIC_SINK_AUDIT_LANGS.contains(&lang)
}

#[cfg(test)]
#[path = "semantic_options_tests.rs"]
mod semantic_options_tests;

#[cfg(test)]
#[path = "source_lineage_tests.rs"]
mod source_lineage_tests;

#[cfg(test)]
#[path = "finding_completeness_tests.rs"]
mod finding_completeness_tests;

#[cfg(test)]
#[path = "match_attribution_tests.rs"]
mod match_attribution_tests;

#[cfg(test)]
#[path = "taint_path_tests.rs"]
mod taint_path_tests;

#[cfg(test)]
mod source_seed_tests {
    use super::*;

    fn service_from_segment(segment: bonsai_idg::segment::IdgSegment) -> bonsai_idg::IdgQueryService {
        let mut workspace = bonsai_idg::IdgWorkspace::new();
        workspace.register_segment(segment);
        bonsai_idg::IdgQueryService::new(
            std::sync::Arc::new(workspace),
            std::sync::Arc::new(bonsai_index::GlobalIndex::new()),
        )
    }

    fn source_decl(events: Vec<FlowEvent>) -> bonsai_lang_api::Decl {
        let span = Span::new(FileId::new(1), 0, 100);
        bonsai_lang_api::Decl {
            symbol: SymbolId::new(1),
            kind: DeclKind::Function,
            name: "handle_request".to_string(),
            qualified_name: None,
            module_path: bonsai_lang_api::ModulePath::default(),
            span,
            name_span: span,
            visibility: bonsai_lang_api::Visibility::Public,
            parent: None,
            body_span: Some(span),
            flow_events: events,
            has_implicit_returns: false,
            params: Vec::new(),
            param_annotations: Vec::new(),
            type_aliases: Vec::new(),
            bases: Vec::new(),
            receiver_param_index: None,
            receiver_field_writes: Vec::new(),
            implicit_receiver_names: Vec::new(),
            receiver_state_sources: Vec::new(),
            return_type: None,
            is_variadic: false,
        }
    }

    fn source_rule_match_at(span: Span) -> RuleMatch {
        RuleMatch {
            origin: MatchOrigin::Rulepack,
            rule_id: "python.flask.request_args_get".to_string(),
            language: "python".to_string(),
            file: "app.py".to_string(),
            line: 1,
            column: 1,
            span,
            match_text: "request.args.get".to_string(),
            enclosing_fn: Some("handle_request".to_string()),
        }
    }

    #[test]
    fn qualified_read_source_seeds_its_own_descendants_not_receiver() {
        let mut seeds = TokenSet::default();
        seed_descendant_aliases_for_qualified_source_reads(
            &mut seeds,
            &["req.query".to_string(), "req.query.theme".to_string()],
            "req.query",
        );

        assert!(seeds.contains("req.query"));
        assert!(seeds.contains("req.query.*"));
        assert!(!seeds.contains("req.*"));
    }

    #[test]
    fn concrete_call_source_seeds_only_overlapping_assignment_site() {
        let file = FileId::new(1);
        let events = vec![
            FlowEvent::Assign {
                span: Span::new(file, 10, 40),
                target: "token".to_string(),
                source_name: None,
                source_call: Some("request.args.get".to_string()),
                source_call_args: vec!["\"token\"".to_string()],
                source_names: vec!["request.args".to_string()],
                value_kind: Some(AssignValueKind::CallResult),
                declares_new_binding: true,
            },
            FlowEvent::Assign {
                span: Span::new(file, 50, 82),
                target: "action".to_string(),
                source_name: None,
                source_call: Some("request.args.get".to_string()),
                source_call_args: vec!["\"action\"".to_string()],
                source_names: vec!["request.args".to_string()],
                value_kind: Some(AssignValueKind::CallResult),
                declares_new_binding: true,
            },
        ];
        let source = source_rule_match_at(Span::new(file, 20, 36));
        let mut seeds = TokenSet::default();

        collect_source_seed_targets(&events, &source, &[], &[], false, &mut seeds);

        assert!(seeds.contains("token"));
        assert!(!seeds.contains("action"));
    }

    #[test]
    fn concrete_call_source_seeds_the_matched_call_result_not_siblings() {
        let file = FileId::new(1);
        let events = vec![
            FlowEvent::Call {
                span: Span::new(file, 10, 30),
                name: "request.args.get".to_string(),
                receiver: Some("request.args".to_string()),
                receiver_types: Vec::new(),
                call_kind: bonsai_lang_api::CallKind::Function,
                args: vec![bonsai_lang_api::CallArg {
                    passing_mode: Default::default(),
                    span: Span::new(file, 27, 30),
                    name: None,
                    value_text: "\"token\"".to_string(),
                    place: None,
                    source_names: Vec::new(),
                }],
            },
            FlowEvent::Call {
                span: Span::new(file, 50, 72),
                name: "other.args.get".to_string(),
                receiver: Some("other.args".to_string()),
                receiver_types: Vec::new(),
                call_kind: bonsai_lang_api::CallKind::Function,
                args: Vec::new(),
            },
        ];
        let source = source_rule_match_at(Span::new(file, 10, 30));
        let mut seeds = TokenSet::default();

        collect_source_seed_targets(&events, &source, &[], &[], false, &mut seeds);

        assert!(seeds.contains("request.args.get"));
        assert!(!seeds.contains("other.args.get"));
    }

    #[test]
    fn concrete_source_without_structured_match_does_not_fallback_to_rule_text() {
        let file = FileId::new(1);
        let decl = source_decl(vec![FlowEvent::Call {
            span: Span::new(file, 50, 72),
            name: "other.args.get".to_string(),
            receiver: Some("other.args".to_string()),
            receiver_types: Vec::new(),
            call_kind: bonsai_lang_api::CallKind::Function,
            args: Vec::new(),
        }]);
        let source = source_rule_match_at(Span::new(file, 10, 30));

        let seeds = source_seed_set(&Rulepack::default(), &source, &decl);

        assert!(
            seeds.is_empty(),
            "concrete expression sources must use their span/structured event evidence, not broad rule-text fallback"
        );
    }

    #[test]
    fn anchored_call_return_seed_nodes_do_not_include_same_name_reads_or_writes() {
        let func = FuncId::new(9);
        let anchor = Span::new(FileId::new(0), 10, 20);
        let later = Span::new(FileId::new(0), 40, 60);
        let mut segment = bonsai_idg::segment::IdgSegment::new();
        let source_name = segment.strings.intern("request.args.get");
        let call_ret = segment.intern_place(bonsai_idg::Place::CallRet {
            site: bonsai_idg::CallSiteId(anchor),
        });
        let same_name_read = segment.intern_place(bonsai_idg::Place::Read {
            name: source_name,
            path: Vec::new().into(),
        });
        let same_name_write = segment.intern_place(bonsai_idg::Place::write(source_name, later));
        segment.intern_node(func, call_ret);
        segment.intern_node(func, same_name_read);
        segment.intern_node(func, same_name_write);
        segment.record_func(func);
        let service = service_from_segment(segment);
        let global = bonsai_index::GlobalIndex::new();
        let seeds = TokenSet::from_iter(["request.args.get".to_string()]);

        let nodes = compose_idg_seed_nodes(
            IdgSeedRequest::rule_match(func, &seeds, Some(anchor), &[]),
            &global,
            &service,
        );
        let ret_ws = service.call_ret_node_at_site(func, anchor).expect("ret node");
        let same_name_nodes = service.read_or_write_nodes_for_names(func, &["request.args.get".to_string()]);

        assert!(nodes.contains(&ret_ws), "anchor CallRet remains a source seed");
        assert!(
            same_name_nodes.iter().all(|node| !nodes.contains(node)),
            "anchored call-return sources must not widen to same-named reads/writes elsewhere in the function"
        );
    }
}

/// Path of `rule`'s source file relative to its
/// `langs/<lang>/<kind>s/` bucket — `crypto.yml`, `subdir/foo.yml`,
/// etc. Public so the CLI tree renderer doesn't have to maintain a
/// drift-prone copy.
pub fn tree_file_rel(pack: &Rulepack, rule: &Rule) -> String {
    let kind_dir = format!("{}s", rule_kind_str(rule.kind));
    let base = pack.root.join("langs").join(&rule.language).join(kind_dir);
    let path = Path::new(&rule.source_path);
    path.strip_prefix(&base)
        .ok()
        .and_then(|rel| rel.to_str())
        .map(std::borrow::ToOwned::to_owned)
        .or_else(|| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(std::borrow::ToOwned::to_owned)
        })
        .unwrap_or_else(|| short_file(&rule.source_path))
}

fn tree_file_path(pack: &Rulepack, lang: &str, kind: &str, rel_file: &str) -> String {
    let root_name = pack
        .root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("security-patterns");
    format!("{root_name}/langs/{lang}/{}s/{rel_file}", kind)
}

fn short_file(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
        .to_string()
}

#[cfg(test)]
mod compute_status_tests;
