//! SDK-level security analyses.
//!
//! This module owns the command-independent orchestration behind
//! `security taint-analysis` and `security source-analysis`. CLI code
//! should call these functions, then handle only formatting, paging,
//! progress UI, and themed rendering.

use crate::deps::{build_inventory, DependencyInventory};
use crate::finding::{
    compute_finding_id, Finding, FindingMatch, FindingStatus, TaintPropagationArg, TaintPropagationStep,
    TaintedArgInfo,
};
use crate::loader::Rulepack;
use crate::matcher::{
    infer_entry_point_sources_for_files_with_progress,
    match_rules_against_facts_for_inventory_with_progress_on_files,
    match_rules_against_facts_for_sink_inventory_with_progress_on_files,
    match_rules_against_facts_for_taint_support_with_progress_on_files,
    match_rules_against_facts_for_taint_with_progress_on_files,
    match_rules_against_facts_with_progress_on_files, rule_match_passes_constraints_with_taint_view,
    InterTaintView, RuleMatch,
};
use crate::rule::{
    ConstraintKind, MatchKind, Rule, RuleKind, RuleTarget, Severity, SourceCallbackArgSemantics,
};
use crate::sanitizer_credit::{sanitizer_credits_sink_tag, sanitizer_tag_is_recognized_non_crediting};
use ahash::{AHashMap, AHashSet};
use anyhow::Result;
use bonsai_common::{FileId, FuncId, Precision, Span, SymbolId};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{AssignValueKind, DeclKind, FlowEvent, LanguageRegistry};
use bonsai_taint::{
    apply_configured_transfer_fixpoint, CallResultPassthrough, CleanOutputOverwrite, EntryTaintGraph,
    InterTaintCaches, InterTaintConfig, OutputArgFlow, ReceiverStatePropagation, SourceCallbackArgs,
    SourceOutputArgs, TaintedCall, TaintedCallEdge, TokenSet, ValueFlowGraph,
};
use bonsai_workspace::Workspace;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{mpsc, Arc, OnceLock};
use std::time::{Duration, Instant};

mod clean_overwrite;
mod findings_build;
mod guard_sanitizers;
mod source_seeds;
mod taint_cache;
mod validation;
use clean_overwrite::{
    clean_conditional_helper_identifier, clean_overwrite_callee_tail, clean_overwrite_target_key,
    clean_overwrite_target_keys, interprocedural_clean_overwrite_kills_lineage_arg,
    looks_like_clean_constant, numeric_literal, quoted_literal, same_function_clean_overwrite_kills_sink_arg,
};
#[cfg(test)]
use clean_overwrite::{
    clean_conditional_value_part, clean_output_call_overwrites_target, try_region_clean_overwrites_target,
    value_part_contains_only_clean_literals,
};
use findings_build::{
    build_pattern_only_findings, make_finding, rule_has_taint_predicate, rule_is_non_taint_sink,
    rule_is_pattern_only_finding, FindingBuildContext,
};
#[cfg(test)]
use guard_sanitizers::header_char_allowlist_condition;
use guard_sanitizers::{
    dev_only_environment_guard_sanitizer, finite_literal_map_lookup_allowlist_sanitizer,
    go_jwt_inline_keyfunc_algorithm_guard_sanitizer, go_same_origin_redirect_helper_guard_sanitizer,
    go_xml_decoder_hardening_sanitizer, guarded_char_append_allowlist_sanitizer,
    java_local_html_escape_helper_return_sanitizer, java_url_ssrf_guard_sanitizer,
    js_ts_local_html_escape_helper_sanitizer, local_ldap_escape_helper_sanitizer,
    nosql_eq_filter_wrapper_sanitizer, python_compiled_regex_guard_sanitizer,
    python_lxml_parser_keyword_sanitizer, python_realpath_containment_guard_sanitizer,
    python_url_ssrf_guard_sanitizer, source_sink_pair_is_low_signal, template_interpolations,
};
#[cfg(test)]
use source_seeds::seed_descendant_aliases_for_qualified_source_reads;
use source_seeds::{
    collect_source_seed_targets, insert_descendant_taint_aliases, insert_taint_aliases,
    security_text_matches_source_strict, seed_source_nodes_from_value_flow,
};
pub use validation::validate_pack;
#[cfg(test)]
use validation::{
    lowercase_receiver_token_from_regex, package_signal_distro_smell, regex_prefix_is_receiver_agnostic,
};

type RankedCallPath = std::cmp::Reverse<(i64, u32, u32, Vec<FuncId>)>;
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
    /// Optional interprocedural `(FuncId, seed)` chunk size. Defaults
    /// to the taint engine's standard chunk size when unset. This is
    /// not a completeness cap; the security driver resumes chunks
    /// until the semantic worklist drains.
    pub interprocedural_budget: Option<u32>,
    /// Optional per-function intraprocedural CFG worklist cap.
    /// Defaults to the CFG-size-derived cap when unset.
    pub intra_worklist_cap: Option<u32>,
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
            interprocedural_budget: None,
            intra_worklist_cap: None,
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
}

// Rendering guard for the current source-flow report shape. Naively
// enumerating every raw trace path can explode even in `examples/`;
// the production-grade exactness follow-up is to report canonical
// reachability summaries or stream an explicit incomplete marker,
// not to silently materialize an unbounded path product in memory.
const SOURCE_ANALYSIS_LINEAGE_RENDER_HOPS: usize = 6;
const SOURCE_ANALYSIS_LINEAGE_RENDER_PATHS: usize = 24;

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
    let options = options.semantic_precision_only();
    let mut sources = select_rules(pack, RuleKind::Source, None, options.source.as_deref(), |r| {
        source_rule_matches_filters(r, options.trust.as_deref(), options.category.as_deref(), None)
    })?;
    let mut sinks = select_rules(pack, RuleKind::Sink, None, options.sink.as_deref(), |r| {
        options
            .severity
            .is_none_or(|min| r.severity.is_some_and(|s| s >= min))
            && options.tag.as_deref().is_none_or(|t| r.tag.as_deref() == Some(t))
    })?;
    let mut sanitizers = select_rules(pack, RuleKind::Sanitizer, None, None, |_| true)?;
    // `returns_type` rules are typing-only: they declare a factory
    // method's return type for receiver-typing and must not themselves
    // produce findings. They are still read (from the full pack) by
    // `build_factory_returns` below. No-op until the pack ships such
    // rules.
    sources.retain(|r| r.returns_type.is_none());
    sinks.retain(|r| r.returns_type.is_none());
    sanitizers.retain(|r| r.returns_type.is_none());
    filter_rules_to_workspace_languages(ws, &mut sources);
    filter_rules_to_workspace_languages(ws, &mut sinks);
    filter_rules_to_workspace_languages(ws, &mut sanitizers);
    let selected_sink_rule_count = sinks.len();

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
        let concrete_param_bases = concrete_source_param_bases(&source_hits);
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

    let endpoint_scan_files =
        endpoint_scan_files_for_taint(ws, &source_hits, &scan_files, options.max_precision);
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
    let factory_returns = crate::matcher::build_factory_returns(&pack.all_rules());
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

    let mut findings_raw = build_findings_chain_aware(
        ws,
        &source_hits,
        &sink_hits,
        &sanitizer_hits,
        pack,
        options.interprocedural_budget,
        options.intra_worklist_cap,
        options.max_precision,
        options.taint_graph_resident_cache_entries,
        &factory_returns,
        &mut on_progress,
    );
    extend_java_mdc_context_logger_findings(&mut findings_raw, &sink_hits, pack, ws);
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
        &pattern_sink_hits,
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
    let mut findings = combine_findings_by_source_flow(findings_raw);
    if let Some(max_precision) = options.max_precision {
        findings.retain(|combined| finding_precision_within(&combined.finding.precision, max_precision));
    }
    if !options.exclude_files.is_empty() || options.exclude_tests {
        findings.retain(|combined| {
            !finding_has_excluded_path(
                ws,
                &combined.finding,
                &options.exclude_files,
                options.exclude_tests,
            )
        });
    }
    if options.exclude_tests {
        // Test-path post-filter — catches cross-file flows where one
        // side wasn't pruned earlier (e.g. prod source → test sink).
        findings.retain(|combined| !combined.finding.from_test);
    }
    if !options.show_sanitized {
        findings.retain(|combined| combined.finding.status != FindingStatus::Sanitized);
    }
    drop_dominated_wrapper_findings(&mut findings);
    drop_dominated_receiver_projection_findings(&mut findings);
    // §C cleanup pass: when `--inferred-sources` synthesizes
    // `entry-point.class_field.inherited` sources for every record/
    // case-class component, each component reaches the sink through
    // the same flat container — so a sink that semantically consumes
    // only the `cmd` component still picks up inferred findings on
    // sibling components (`this.kind`, `this.user`). Drop those
    // sibling-attributed findings when (a) a concrete source already
    // covers the same chain end-to-end, and (b) the inferred source's
    // field name doesn't appear in any of the sink's `tainted_args`.
    findings = drop_field_mismatched_inferred_findings(findings);
    if let Some(flow_id) = options.flow_id.as_deref() {
        findings.retain(|combined| {
            combined
                .finding
                .representative_flow_id
                .as_deref()
                .is_some_and(|candidate| candidate == flow_id)
        });
    }
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
                source_reporting_rank(&a.finding.source).cmp(&source_reporting_rank(&b.finding.source))
            })
            .then_with(|| a.finding.finding_id.cmp(&b.finding.finding_id))
    });
    on_progress(AnalysisProgress::PhaseFinished);

    if options.attach_flow_evidence {
        // Embed per-hop source bodies so JSON/SARIF carry the same code the text
        // view renders. Done last, on surviving findings only, so filtered-out
        // findings never pay the VFS read.
        on_progress(AnalysisProgress::PhaseStarted {
            label: "attaching flow evidence",
            total: findings.len() as u64,
        });
        let mut flow_body_cache = crate::flow_evidence::FlowBodyCache::new(ws);
        for combined in &mut findings {
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

    Ok(TaintAnalysisReport {
        findings,
        source_rule_count: sources.len(),
        sink_rule_count: selected_sink_rule_count,
        sanitizer_rule_count: sanitizers.len(),
    })
}

const LARGE_TAINT_ENDPOINT_PREFILTER_FILE_THRESHOLD: usize = 10_000;

fn endpoint_scan_files_for_taint(
    ws: &Workspace,
    source_hits: &[RuleMatch],
    scan_files: &[FileId],
    max_precision: Option<Precision>,
) -> Vec<FileId> {
    if scan_files.len() < LARGE_TAINT_ENDPOINT_PREFILTER_FILE_THRESHOLD || source_hits.is_empty() {
        return scan_files.to_vec();
    }
    let mut source_funcs: Vec<FuncId> = source_hits
        .iter()
        .filter_map(|source| func_id_for_match(ws, source))
        .collect();
    source_funcs.sort_by_key(|func| func.raw());
    source_funcs.dedup();
    if source_funcs.is_empty() {
        return scan_files.to_vec();
    }

    let reachable = ws.source_reachable_resolved_call_graph(&source_funcs, &[], max_precision);
    let allowed_files: AHashSet<FileId> = scan_files.iter().copied().collect();
    let mut endpoint_files: Vec<FileId> = reachable
        .files
        .into_iter()
        .filter(|file| allowed_files.contains(file))
        .collect();
    endpoint_files.sort_by_key(|file| file.raw());
    endpoint_files.dedup();
    if endpoint_files.is_empty() {
        return scan_files.to_vec();
    }
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "large taint endpoint scan reduced files={} -> {} source_funcs={} reachable_funcs={}",
        scan_files.len(),
        endpoint_files.len(),
        source_funcs.len(),
        reachable.funcs.len()
    );
    endpoint_files
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
    let mut sources = select_rules(pack, RuleKind::Source, None, options.source.as_deref(), |r| {
        source_rule_matches_filters(
            r,
            options.trust.as_deref(),
            options.category.as_deref(),
            options.tag.as_deref(),
        )
    })?;
    filter_rules_to_workspace_languages(ws, &mut sources);

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
        let concrete_param_bases = concrete_source_param_bases(&source_hits);
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
    on_progress(AnalysisProgress::Note {
        label: "scope",
        detail: format!("source-analysis source_matches={}", source_hits.len()),
    });

    let global = ws.db().global_index();
    let transfer_languages = workspace_languages(ws);
    let source_graph_config = InterTaintConfig {
        sanitizers: TokenSet::default(),
        budget: InterTaintConfig::default().budget,
        intra_worklist_cap: None,
        source_bearing_functions: AHashSet::default(),
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
        ..Default::default()
    };
    // Exact source-seeded graphs are cached through the workspace
    // `TaintGraphIndex`, which is bounded in memory and keyed by a
    // rule/config fingerprint. Disk persistence is best-effort and
    // default-on so repeated CLI runs can stay warm; set
    // `BONSAI_TAINT_GRAPH_PERSIST=0` to disable the performance
    // artifact without changing analysis results.
    let workspace_taint_index = ws.taint_index();
    let source_graph_caches = ws.inter_taint_caches();
    let source_graph_fingerprint =
        taint_cache::config_fingerprint(pack, "source-analysis", source_graph_config.max_edge_precision);
    let cache_report = taint_cache::prepare_workspace_cache(ws, "source-analysis", source_graph_fingerprint);
    on_progress(AnalysisProgress::Note {
        label: "taint-cache",
        detail: cache_report.detail(),
    });
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
    let mut hits_by_func: AHashMap<FuncId, Vec<SourceHitForFunction<'_>>> = AHashMap::new();
    for (idx, hit) in source_hits.iter().enumerate() {
        let Some(source_match) = source_finding_match(hit, pack) else {
            continue;
        };
        let Some(start) = func_id_for_match(ws, hit) else {
            continue;
        };
        hits_by_func.entry(start).or_default().push(SourceHitForFunction {
            index: idx,
            hit,
            source_match,
        });
    }
    let mut hits_by_func_sorted: Vec<(FuncId, Vec<SourceHitForFunction<'_>>)> =
        hits_by_func.into_iter().collect();
    hits_by_func_sorted.sort_by_key(|(_, hits)| hits.first().map(|hit| hit.index).unwrap_or(usize::MAX));
    let source_function_count = hits_by_func_sorted.len();

    let mut source_jobs: Vec<(usize, SourceGraphJob)> = Vec::new();
    for (start, hits) in hits_by_func_sorted {
        let Some(decl) = global.decl_of(SymbolId::new(start.raw())) else {
            continue;
        };
        for hit in hits {
            let seeds = source_seed_set(pack, hit.hit, decl, None);
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
    source_jobs.sort_by_key(|(idx, _)| *idx);
    let mut source_groups: Vec<SourceGraphGroup> = Vec::new();
    let mut group_by_key: AHashMap<(FuncId, Vec<String>), usize> = AHashMap::new();
    for (idx, job) in source_jobs {
        let group_key = (job.start, job.graph_key.clone());
        if let Some(&group_idx) = group_by_key.get(&group_key) {
            source_groups[group_idx].jobs.push(job);
        } else {
            let group_idx = source_groups.len();
            group_by_key.insert(group_key, group_idx);
            source_groups.push(SourceGraphGroup {
                first_index: idx,
                start: job.start,
                graph_key: job.graph_key.clone(),
                lineage_funcs: None,
                jobs: vec![job],
            });
        }
    }
    source_groups.sort_by_key(|group| group.first_index);
    on_progress(AnalysisProgress::Note {
        label: "scope",
        detail: format!(
            "source-analysis source_jobs={} source_graph_groups={} functions={}",
            source_groups.iter().map(|group| group.jobs.len()).sum::<usize>(),
            source_groups.len(),
            source_function_count
        ),
    });
    if !source_groups.is_empty() {
        on_progress(AnalysisProgress::PhaseStarted {
            label: "building source lineage scope",
            total: source_groups.len() as u64 + 2,
        });
        let source_call_graph = ws.cached_resolved_call_graph();
        source_graph_caches.seed_resolved_call_graph(source_call_graph.as_ref());
        on_progress(AnalysisProgress::PhaseTicked);
        let mut scoped_func_set: AHashSet<FuncId> = AHashSet::default();
        for group in &mut source_groups {
            let source_lineage_funcs = source_analysis_lineage_func_scope(
                group.start,
                global.as_ref(),
                source_call_graph.as_ref(),
                source_graph_config.max_edge_precision,
                options.lineage_limits.max_hops,
            );
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
            .filter_map(|func| global.declaring_file(SymbolId::new(func.raw())))
            .collect();
        scoped_files.sort_by_key(|file| file.raw());
        scoped_files.dedup();
        ensure_workspace_files_indexed(ws, &scoped_files);
        seed_idg_service_for_rulepack_for_files(
            ws,
            pack,
            &transfer_languages,
            &scoped_files,
            &scoped_funcs,
            source_call_graph.as_ref(),
        );
        on_progress(AnalysisProgress::PhaseTicked);
        on_progress(AnalysisProgress::PhaseFinished);
    }
    let total_source_path_ticks = source_hits.len();
    on_progress(AnalysisProgress::PhaseStarted {
        label: "enumerating source paths",
        total: total_source_path_ticks as u64,
    });
    let build_group_candidates = |group: &SourceGraphGroup| -> Vec<SourceAnalysisCandidate> {
        let graph = workspace_taint_index
            .get(group.start, &group.graph_key)
            .unwrap_or_else(|| {
                let first = &group.jobs[0];
                let graph = Arc::new(exact_source_path_graph(
                    group.start,
                    &first.seeds,
                    &source_graph_config,
                    ws.db(),
                    source_graph_caches,
                    ws,
                    first.anchor,
                    &first.output_arg_names,
                    group.lineage_funcs.as_ref(),
                    group.lineage_funcs.as_ref(),
                ));
                workspace_taint_index.insert_if_absent(group.start, group.graph_key.clone(), graph)
            });
        let mut local: Vec<SourceAnalysisCandidate> = Vec::new();
        for job in &group.jobs {
            let mut seen_chains: AHashSet<Vec<String>> = AHashSet::new();
            let (lineages, lineage_stats) = collect_tainted_source_lineages(
                &graph.call_records,
                job.start,
                options.lineage_limits.max_hops,
                options.lineage_limits.max_paths,
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
                let Some(chain_names) = chain_names_for_path(ws, &path) else {
                    continue;
                };
                if !seen_chains.insert(chain_names.clone()) {
                    continue;
                }
                let taint_path = taint_path_for_lineage(ws, &emission.records, None);
                let flow_id = flow_id_for_taint_path(&chain_names, &taint_path);
                let precision = chain_precision_for_records(&emission.records);
                if !precision.is_semantic() {
                    continue;
                }
                local.push(SourceAnalysisCandidate {
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
                let Some(chain_names) = chain_names_for_path(ws, &path) else {
                    continue;
                };
                let taint_path = Vec::new();
                let flow_id = flow_id_for_taint_path(&chain_names, &taint_path);
                local.push(SourceAnalysisCandidate {
                    source: job.source_match.clone(),
                    path,
                    flow_id,
                    chain_names,
                    taint_path,
                    precision: Precision::Exact,
                    lineage: SourceLineageStatus::complete(),
                });
                continue;
            }
        }
        local
    };
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
                                    .map(|(idx, group)| {
                                        let candidates = build_group_candidates(group);
                                        let _ = tx.send(group.jobs.len());
                                        (idx, candidates)
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
                        // A panicking worker must surface, not silently yield zero
                    // findings: `unwrap_or_default()` would turn a crashed scan
                    // into a clean "nothing found" result. Re-raise the payload
                    // on the scope thread so the failure is visible.
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
                    .map(|(idx, group)| {
                        let candidates = build_group_candidates(group);
                        for _ in 0..group.jobs.len() {
                            on_progress(AnalysisProgress::PhaseTicked);
                        }
                        (idx, candidates)
                    })
                    .collect(),
            }
        } else {
            source_groups
                .iter()
                .enumerate()
                .map(|(idx, group)| {
                    let candidates = build_group_candidates(group);
                    for _ in 0..group.jobs.len() {
                        on_progress(AnalysisProgress::PhaseTicked);
                    }
                    (idx, candidates)
                })
                .collect()
        };
    grouped_candidates.sort_by_key(|(idx, _)| *idx);
    // Per-group output Vecs are merged at the end; the second
    // `seen` pass below is a canonicalisation step.
    let parallel_candidates: Vec<SourceAnalysisCandidate> = grouped_candidates
        .into_iter()
        .flat_map(|(_, candidates)| candidates)
        .collect();

    // Single-threaded canonicalisation: stable first-occurrence dedupe
    // across the par-collected candidates.
    //
    // Key on the rendered identity `(source-site, displayed-chain)`, not
    // `flow_id` — the flow id carries taint-path detail that never reaches
    // the panel, so two lineages that render the same chain would be
    // reported twice. Ambiguous virtual dispatch can emit the same function
    // set in different internal orders; keeping the first (call-graph
    // ordered) drops the spurious reversed ordering.
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
        if let Some(&idx) = seen.get(&dedupe_key) {
            merge_source_lineage_status(&mut candidates[idx].lineage, candidate.lineage);
            candidates[idx].precision = candidates[idx].precision.meet(candidate.precision);
        } else {
            let idx = candidates.len();
            seen.insert(dedupe_key, idx);
            candidates.push(candidate);
        }
    }
    let emitted_source_path_ticks: usize = source_groups.iter().map(|group| group.jobs.len()).sum();
    for _ in emitted_source_path_ticks..total_source_path_ticks {
        on_progress(AnalysisProgress::PhaseTicked);
    }
    on_progress(AnalysisProgress::PhaseFinished);

    if !options.exclude_files.is_empty() || options.exclude_tests {
        candidates.retain(|candidate| {
            !source_candidate_has_excluded_path(ws, candidate, &options.exclude_files, options.exclude_tests)
        });
    }
    let candidates = combine_source_analysis_candidates(candidates);
    let lineage_summary = SourceLineageSummary::from_candidates(&candidates);
    if let Some(written) = taint_cache::finish_workspace_cache(ws) {
        on_progress(AnalysisProgress::Note {
            label: "taint-cache",
            detail: format!("finish write-through entries={written}"),
        });
    } else {
        on_progress(AnalysisProgress::Note {
            label: "taint-cache",
            detail: "finish write-through failed".to_string(),
        });
    }
    Ok(SourceAnalysisReport {
        candidates,
        source_rule_count: sources.len(),
        lineage_summary,
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
    let mut matches = gather_inventory_matches_phased(
        ws,
        &selected,
        "matching source rules",
        &scan_files,
        total_files,
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
    on_progress(AnalysisProgress::PhaseStarted {
        label: "matching sink rules",
        total: scan_files.len() as u64,
    });
    let mut matches = match_rules_against_facts_for_sink_inventory_with_progress_on_files(
        ws,
        &selected,
        &scan_files,
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
    let mut matches = gather_inventory_matches_phased(
        ws,
        &selected,
        "matching sanitizer rules",
        &scan_files,
        total_files,
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
    on_progress: &mut F,
) -> Vec<RuleMatch>
where
    F: FnMut(AnalysisProgress),
{
    on_progress(AnalysisProgress::PhaseStarted {
        label,
        total: total_files,
    });
    let matches = match_rules_against_facts_with_progress_on_files(ws, rules, scan_files, || {
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
    on_progress: &mut F,
) -> Vec<RuleMatch>
where
    F: FnMut(AnalysisProgress),
{
    on_progress(AnalysisProgress::PhaseStarted {
        label,
        total: total_files,
    });
    let matches =
        match_rules_against_facts_for_taint_support_with_progress_on_files(ws, rules, scan_files, || {
            on_progress(AnalysisProgress::PhaseTicked);
        });
    on_progress(AnalysisProgress::PhaseFinished);
    matches
}

fn gather_inventory_matches_phased<F>(
    ws: &Workspace,
    rules: &[&Rule],
    label: &'static str,
    scan_files: &[FileId],
    total_files: u64,
    on_progress: &mut F,
) -> Vec<RuleMatch>
where
    F: FnMut(AnalysisProgress),
{
    on_progress(AnalysisProgress::PhaseStarted {
        label,
        total: total_files,
    });
    let matches =
        match_rules_against_facts_for_inventory_with_progress_on_files(ws, rules, scan_files, || {
            on_progress(AnalysisProgress::PhaseTicked);
        });
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
fn concrete_source_param_bases(hits: &[RuleMatch]) -> AHashMap<(String, String), AHashSet<String>> {
    let mut out: AHashMap<(String, String), AHashSet<String>> = AHashMap::default();
    for hit in hits {
        if hit.rule_id.starts_with("entry-point.") {
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
    if !inferred.rule_id.starts_with("entry-point.") {
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
    if hit.rule_id.starts_with("entry-point.") {
        return trust.is_none_or(|t| t == "local")
            && category.is_none_or(|c| c == "inferred")
            && tag.is_none_or(|t| t == "entry-point");
    }
    pack.find_rule_by_id(&hit.rule_id)
        .is_some_and(|rule| source_rule_matches_filters(rule, trust, category, tag))
}

fn source_finding_match(hit: &RuleMatch, pack: &Rulepack) -> Option<FindingMatch> {
    if hit.rule_id.starts_with("entry-point.") {
        Some(FindingMatch::from_inferred(hit))
    } else {
        pack.find_rule_by_id(&hit.rule_id)
            .map(|rule| FindingMatch::from_rule_match(hit, rule))
    }
}

fn func_id_for_match(ws: &Workspace, hit: &RuleMatch) -> Option<FuncId> {
    let expected_name = hit.enclosing_fn.as_deref();
    if let Some(entry) = ws
        .enclosing_index()
        .enclosing_for(ws.db(), hit.span.file, hit.span.start)
    {
        if expected_name.is_none_or(|name| name == entry.name) {
            return Some(FuncId::new(entry.symbol.raw()));
        }
    }

    let name = expected_name?;
    let global = ws.db().global_index();
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

fn semantic_precision_for_edges(edges: &[&bonsai_callgraph::CallEdge]) -> Precision {
    edges
        .iter()
        .fold(Precision::Exact, |precision, edge| precision.meet(edge.precision))
}

fn chain_funcs_for_semantic_edges(
    source_func: FuncId,
    edges: &[&bonsai_callgraph::CallEdge],
) -> Option<Vec<FuncId>> {
    if edges.is_empty() {
        return Some(vec![source_func]);
    }
    let first = edges.first()?;
    if first.from != source_func {
        return None;
    }
    let mut funcs = Vec::with_capacity(edges.len() + 1);
    funcs.push(source_func);
    for edge in edges {
        if funcs.last().copied() != Some(edge.from) {
            return None;
        }
        funcs.push(edge.to);
    }
    Some(funcs)
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
    fn new(global: &bonsai_index::GlobalIndex, graph: &EntryTaintGraph) -> Self {
        let resolved_sites: AHashSet<(FuncId, Span)> = graph
            .call_records
            .iter()
            .map(|record| (record.caller, record.call_span))
            .collect();
        let mut seen_sites: AHashSet<(FuncId, Span)> = AHashSet::new();
        let mut by_caller: AHashMap<FuncId, Vec<UnresolvedWorkspaceCallSite>> = AHashMap::new();
        for call in &graph.tainted_calls {
            if !matches!(call.kind, bonsai_taint::TaintedCallKind::Call)
                || resolved_sites.contains(&(call.caller, call.call_span))
                || !seen_sites.insert((call.caller, call.call_span))
            {
                continue;
            }
            if workspace_has_callable_named_in_context(global, call.caller, &call.name) {
                by_caller
                    .entry(call.caller)
                    .or_default()
                    .push(UnresolvedWorkspaceCallSite {
                        span: call.call_span,
                        name: call.name.clone(),
                    });
            }
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

fn workspace_has_callable_named_in_context(
    global: &bonsai_index::GlobalIndex,
    caller: FuncId,
    name: &str,
) -> bool {
    let Some(caller_decl) = global.decl_of(SymbolId::new(caller.raw())) else {
        return false;
    };
    let caller_file = global
        .declaring_file(caller_decl.symbol)
        .unwrap_or(caller_decl.span.file);
    let ctx = bonsai_resolve::ResolveContext::new(caller_file, &caller_decl.module_path);
    let short = bonsai_lang_api::kit::short_name_of(name);
    [name, short].into_iter().any(|candidate| {
        !candidate.is_empty()
            && !bonsai_resolve::resolve_callable_with_context(global, candidate, &ctx).is_empty()
    })
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
    graph_saturated: bool,
) -> Option<CallEvidence> {
    // Public findings are semantic-only. A saturated graph means the
    // requested source scope did not produce complete evidence, so do
    // not downgrade it to a broad precision class and report it as a
    // finding. Current IDG-backed graphs are built to completion and
    // set `saturated = false`; this guard protects compatibility
    // callers that still hand in an older graph shape.
    if graph_saturated {
        return None;
    }
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
            let semantic_edges =
                canonical_chain_index.semantic_edges_along_best_path(source_func, call.caller)?;
            let chain_funcs = chain_funcs_for_semantic_edges(source_func, &semantic_edges)?;
            let chain_precision = semantic_precision_for_edges(&semantic_edges)
                .meet(chain_precision_for_records(&original_records));
            let sanitizer_candidate_funcs = sanitizer_candidate_funcs_for_chain(&chain_funcs);
            let taint_path = taint_path_for_semantic_edges(ws, source_func, &semantic_edges, Some(call));
            (
                chain_funcs,
                sanitizer_candidate_funcs,
                chain_precision,
                taint_path,
            )
        };
    if !chain_precision.is_semantic() {
        return None;
    }
    let chain_names = chain_names_for_path(ws, &chain_funcs)?;
    let mut sink_tainted_args: Vec<TaintedArgInfo> = call
        .tainted_args
        .iter()
        .map(|arg| TaintedArgInfo {
            index: arg.index,
            value_text: arg.value_text.clone(),
        })
        .collect();
    if let Some(receiver) = call.tainted_receiver.as_deref() {
        sink_tainted_args.push(TaintedArgInfo {
            index: usize::MAX,
            value_text: receiver.to_string(),
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

fn sanitizer_candidate_funcs_for_chain(chain_funcs: &[FuncId]) -> Vec<FuncId> {
    let mut funcs = Vec::with_capacity(chain_funcs.len());
    for func in chain_funcs {
        push_unique_func(&mut funcs, *func);
    }
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
/// strictly reduces synthetic-edge count AND covers at least as many
/// distinct functions. Otherwise the original chain is returned.
struct CanonicalChainIndex<'a> {
    adjacency: AHashMap<FuncId, Vec<(FuncId, bool)>>,
    edge_has_any: AHashSet<(FuncId, FuncId)>,
    edge_has_real: AHashSet<(FuncId, FuncId)>,
    /// Representative record per edge — a real (non-synthetic) one when
    /// any exists. Lets a canonically rewritten chain rebuild its
    /// taint_path from the actual recorded propagation on each hop.
    edge_record: AHashMap<(FuncId, FuncId), &'a TaintedCallEdge>,
    semantic_adjacency: AHashMap<FuncId, Vec<&'a bonsai_callgraph::CallEdge>>,
    semantic_edge: AHashMap<(FuncId, FuncId), &'a bonsai_callgraph::CallEdge>,
}

type SemanticPathHeapItem = std::cmp::Reverse<(u32, u8, u8, Vec<FuncId>)>;

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
        let mut semantic_adjacency: AHashMap<FuncId, Vec<&'a bonsai_callgraph::CallEdge>> =
            AHashMap::default();
        let mut semantic_edge: AHashMap<(FuncId, FuncId), &'a bonsai_callgraph::CallEdge> =
            AHashMap::default();
        for edge in call_graph
            .inner()
            .edges
            .iter()
            .filter(|edge| edge.precision.is_semantic())
        {
            semantic_adjacency.entry(edge.from).or_default().push(edge);
            semantic_edge
                .entry((edge.from, edge.to))
                .and_modify(|existing| {
                    if edge.precision < existing.precision
                        || (edge.precision == existing.precision
                            && (edge.span.file.raw(), edge.span.start, edge.span.end)
                                < (existing.span.file.raw(), existing.span.start, existing.span.end))
                    {
                        *existing = edge;
                    }
                })
                .or_insert(edge);
        }
        for edges in semantic_adjacency.values_mut() {
            edges.sort_by_key(|edge| {
                (
                    edge.to.raw(),
                    edge.precision.rank(),
                    edge.span.file.raw(),
                    edge.span.start,
                    edge.span.end,
                )
            });
        }
        Self {
            adjacency,
            edge_has_any,
            edge_has_real,
            edge_record,
            semantic_adjacency,
            semantic_edge,
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

    fn semantic_edges_along_best_path(
        &self,
        source_func: FuncId,
        terminal_func: FuncId,
    ) -> Option<Vec<&'a bonsai_callgraph::CallEdge>> {
        if source_func == terminal_func {
            return Some(Vec::new());
        }
        const MAX_HOPS: usize = 16;
        use std::collections::BinaryHeap;
        let mut heap: BinaryHeap<SemanticPathHeapItem> = BinaryHeap::new();
        heap.push(std::cmp::Reverse((0, 0, 0, vec![source_func])));
        let mut best_score: AHashMap<FuncId, u32> = AHashMap::default();
        best_score.insert(source_func, 0);
        while let Some(std::cmp::Reverse((score, worst_rank, hops, path))) = heap.pop() {
            let current = *path.last()?;
            if current == terminal_func && path.len() > 1 {
                return path
                    .windows(2)
                    .map(|pair| self.semantic_edge.get(&(pair[0], pair[1])).copied())
                    .collect();
            }
            if path.len() > MAX_HOPS {
                continue;
            }
            if best_score.get(&current).copied().unwrap_or(u32::MAX) < score {
                continue;
            }
            let Some(edges) = self.semantic_adjacency.get(&current) else {
                continue;
            };
            for edge in edges {
                if path.contains(&edge.to) {
                    continue;
                }
                let next_rank = worst_rank.max(edge.precision.rank());
                let next_hops = hops.saturating_add(1);
                let next_score = u32::from(next_rank) * 100 + u32::from(next_hops);
                if best_score.get(&edge.to).copied().unwrap_or(u32::MAX) <= next_score {
                    continue;
                }
                best_score.insert(edge.to, next_score);
                let mut next_path = path.clone();
                next_path.push(edge.to);
                heap.push(std::cmp::Reverse((next_score, next_rank, next_hops, next_path)));
            }
        }
        None
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
    let Some(alt) = best_chain_through_real_edges(index, source_func, terminal_func) else {
        return primary;
    };
    // Reject degenerate alternatives (shorter than primary).
    if alt.len() < primary.len() {
        return primary;
    }
    let alt_synth = chain_synth_count(&alt, index);
    let primary_real = primary.len().saturating_sub(1).saturating_sub(primary_synth);
    let alt_real = alt.len().saturating_sub(1).saturating_sub(alt_synth);
    // Prefer chain with more real hops (more informative call
    // sequence). On ties, prefer fewer synthetic hops. On further
    // ties, keep the primary (parent_trace_id-derived chain).
    let alt_is_better = alt_real > primary_real || (alt_real == primary_real && alt_synth < primary_synth);
    if alt_is_better {
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
    record
        .tainted_args
        .iter()
        .all(|arg| arg.index == usize::MAX || arg.index == 255)
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
/// `terminal_func` whose chain-quality score is best (lowest).
/// Score = `100 * synthetic_hops − real_hops` — fewer synthetic
/// edges wins outright; on ties, MORE real hops wins (longer chain
/// is more informative when the synth count matches). Cap the
/// search at `MAX_HOPS` per path so degenerate fanouts don't
/// blow up the heap.
fn best_chain_through_real_edges(
    index: &CanonicalChainIndex<'_>,
    source_func: FuncId,
    terminal_func: FuncId,
) -> Option<Vec<FuncId>> {
    const MAX_HOPS: usize = 16;
    fn score(synth: u32, real: u32) -> i64 {
        100i64 * (synth as i64) - (real as i64)
    }
    use std::collections::BinaryHeap;
    // State: (score, synth, real, path). Pop lowest score first.
    let mut heap: BinaryHeap<RankedCallPath> = BinaryHeap::new();
    heap.push(std::cmp::Reverse((score(0, 0), 0, 0, vec![source_func])));
    let mut best_score: AHashMap<FuncId, i64> = AHashMap::default();
    best_score.insert(source_func, score(0, 0));
    while let Some(std::cmp::Reverse((s, synth, real, path))) = heap.pop() {
        let cur = *path.last().unwrap();
        if cur == terminal_func && path.len() > 1 {
            return Some(path);
        }
        if path.len() >= MAX_HOPS {
            continue;
        }
        if best_score.get(&cur).copied().unwrap_or(i64::MAX) < s {
            continue;
        }
        let Some(neighbors) = index.adjacency.get(&cur) else {
            continue;
        };
        for &(next_f, is_synth) in neighbors {
            if path.contains(&next_f) {
                continue;
            }
            let next_synth = synth + u32::from(is_synth);
            let next_real = real + u32::from(!is_synth);
            let next_score = score(next_synth, next_real);
            if best_score.get(&next_f).copied().unwrap_or(i64::MAX) <= next_score {
                continue;
            }
            best_score.insert(next_f, next_score);
            let mut next_path = path.clone();
            next_path.push(next_f);
            heap.push(std::cmp::Reverse((next_score, next_synth, next_real, next_path)));
        }
    }
    None
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
    // Collapse synthetic `Return → CallRet` round trips that bring
    // the chain back to a function it already visited. Each
    // `arg_idx = u8::MAX` edge in `records` adds a "callee returned
    // to caller" hop, so chains like `handle → transform → handle`
    // (the `g1_c_return` shape: source seeds in `handle`, sink
    // also in `handle`, the chain goes out to `transform` and
    // returns) and `handleRequest → updateUser → handleRequest`
    // (the SDK Java micro case) walk the same physical call site
    // twice on paper. Dedup adjacent revisits so the chain reads
    // as the real distinct-frame path, while still rejecting true
    // cycles (`A → B → A → B`) where a function recurs after
    // intervening frames have advanced past it.
    let mut seen: AHashSet<FuncId> = AHashSet::with_capacity(funcs.len());
    let mut deduped: Vec<FuncId> = Vec::with_capacity(funcs.len());
    for f in funcs.iter().copied() {
        if deduped.last().copied() == Some(f) {
            continue;
        }
        if deduped.contains(&f) && deduped.last().copied() != Some(f) {
            // Function reappears non-adjacently after intervening
            // hops — pop hops until we're back at the prior visit
            // of `f`, treating the intermediate frames as a
            // round-trip artefact (synthetic Return inflated the
            // chain). The chain semantically ends at this revisit.
            while deduped.last().copied() != Some(f) {
                deduped.pop();
            }
            continue;
        }
        deduped.push(f);
        seen.insert(f);
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

fn taint_path_for_semantic_edges(
    ws: &Workspace,
    source_func: FuncId,
    edges: &[&bonsai_callgraph::CallEdge],
    terminal_call: Option<&TaintedCall>,
) -> Vec<TaintPropagationStep> {
    let mut funcs = Vec::with_capacity(edges.len() + 2);
    funcs.push(source_func);
    for edge in edges {
        funcs.push(edge.to);
    }
    if let Some(call) = terminal_call {
        funcs.push(call.caller);
    }
    funcs.sort_unstable();
    funcs.dedup();
    let names = path_display_names_for_funcs(ws, &funcs);
    let mut path: Vec<TaintPropagationStep> = edges
        .iter()
        .map(|edge| propagation_step_for_semantic_edge(ws, edge, &names))
        .collect();
    if let Some(call) = terminal_call {
        path.push(propagation_step_for_terminal_call(ws, call, &names));
    }
    normalize_taint_path(path)
}

fn propagation_step_for_semantic_edge(
    ws: &Workspace,
    edge: &bonsai_callgraph::CallEdge,
    names: &AHashMap<FuncId, String>,
) -> TaintPropagationStep {
    let (file, line, column) = resolve_span_location(ws, edge.span);
    TaintPropagationStep {
        caller: path_display_name(ws, names, edge.from),
        callee: path_display_name(ws, names, edge.to),
        file,
        line,
        column,
        tainted_args: Vec::new(),
    }
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

fn path_display_names_for_funcs(ws: &Workspace, funcs: &[FuncId]) -> AHashMap<FuncId, String> {
    let mut by_name: BTreeMap<String, Vec<FuncId>> = BTreeMap::new();
    for func in funcs {
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
    ws.db()
        .global_index()
        .decl_of(SymbolId::new(func.raw()))
        .map(|decl| decl.name.clone())
        .unwrap_or_else(|| format!("func#{}", func.raw()))
}

fn func_display_name_with_site(ws: &Workspace, func: FuncId) -> String {
    let global = ws.db().global_index();
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
    let global = ws.db().global_index();
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

/// Stable matcher-output sort: language, file, line, column. Required
/// for deterministic finding ids across runs (chain seeding hits the
/// pair budget in input order).
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
    let global = ws.db().global_index();
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

/// True when two source matches point at the same concrete source
/// location, regardless of which alias rule matched it.
fn same_source_location(a: &FindingMatch, b: &FindingMatch) -> bool {
    a.file == b.file && a.line == b.line && a.column == b.column
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
        let is_class_field = f.source.rule_id.contains(".class_field.inherited");
        let is_unreferenced_entry = f.source.rule_id.contains(".unreferenced_entry.");
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
    source.rule_id.starts_with("entry-point.")
        || source.rule_id.contains(".unreferenced_entry.")
        || source.rule_id.contains(".class_field.inherited")
        || source.category.as_deref() == Some("inferred")
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
fn source_preference_rank_for_sink(source: &FindingMatch, sink: Option<&FindingMatch>) -> u8 {
    if source.rule_id.starts_with("entry-point.")
        || source.rule_id.contains(".unreferenced_entry.")
        || source.rule_id.contains(".class_field.inherited")
        || source.category.as_deref() == Some("inferred")
    {
        return 30;
    }
    let base = match source.trust.as_deref() {
        Some("remote") => 0,
        Some("service" | "ipc" | "database" | "library") => 5,
        Some("local" | "config" | "physical") => 10,
        _ => 15,
    };
    let Some(sink) = sink else { return base };
    // Build searchable tokens by concatenating each side's
    // category + tag + rule_id. `contains()` does substring match,
    // so "cli" matches "cli-input", "command" matches
    // "command-injection", etc.
    let sink_token = format!(
        "{} {} {}",
        sink.category.as_deref().unwrap_or(""),
        sink.tag.as_deref().unwrap_or(""),
        sink.rule_id,
    );
    let src_token = format!(
        "{} {} {}",
        source.category.as_deref().unwrap_or(""),
        source.tag.as_deref().unwrap_or(""),
        source.rule_id,
    );
    // Sink class — process-exec / cmd-injection vs xss/browser/html.
    let sink_is_process =
        sink_token.contains("process-exec") || sink_token.contains("command") || sink_token.contains("cmdi");
    let sink_is_browser =
        sink_token.contains("xss") || sink_token.contains("browser") || sink_token.contains("html");
    // Source class — process/cli input vs http/web input.
    let src_is_process_or_cli = src_token.contains("cli")
        || src_token.contains("stdin")
        || src_token.contains("process-input")
        || src_token.contains("file-read")
        || src_token.contains("readline");
    let src_is_http =
        src_token.contains("http") || src_token.contains("web") || src_token.contains("servlet");
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

fn source_specificity_rank(source: &FindingMatch) -> u8 {
    if source.rule_id.contains("request_json_field_get") {
        return 0;
    }
    if source.rule_id.contains("request_get_json") || source.rule_id.ends_with(".request_json") {
        return 5;
    }
    2
}

fn source_reporting_rank(source: &FindingMatch) -> u8 {
    if source.rule_id == "java.source.bytes_blob_param" {
        return 10;
    }
    if source.tag.as_deref() == Some("caller-input") && source.trust.as_deref() != Some("remote") {
        return 5;
    }
    0
}

/// True when two sink-side `FindingMatch`es refer to the exact same
/// call-site. Symmetric counterpart to [`same_source_site`].
fn same_sink_site(a: &FindingMatch, b: &FindingMatch) -> bool {
    a.rule_id == b.rule_id && a.file == b.file && a.line == b.line && a.column == b.column
}

fn combine_findings_by_source_flow(mut findings: Vec<FindingWithChain>) -> Vec<CombinedFindingWithChain> {
    let mut groups: Vec<CombinedFindingWithChain> = Vec::new();
    let mut index: AHashMap<String, usize> = AHashMap::new();

    // Stable-sort so that within each `(language, group_id, flow id, sink site)`
    // bucket — which is what `combined_finding_key` collapses into one
    // group — the most specific source becomes the primary one preserved
    // on the merged finding. The combiner's `merge_finding_into_group`
    // keeps the first-seen finding's source AND flow evidence
    // (`chain_display` / `taint_path` / `representative_flow_id` /
    // `chain_funcs`) as primary and demotes other members' sources to
    // `additional_sources`, dropping their evidence.
    //
    // The ordering here MUST therefore agree with the source ranking
    // `finalize_combined_finding` applies later
    // (`source_preference_rank_for_sink`, then source location, then
    // rule id). If the two disagree, finalize promotes a merged member's
    // source onto a finding that kept a DIFFERENT member's flow
    // evidence — the reported source then never appears on the reported
    // path and the hops carry no source-role line. Within a bucket every
    // member shares the same sink site and rule, so ranking against the
    // member's own sink is the same as ranking against the merged
    // group's primary sink.
    findings.sort_by(|a, b| {
        // Sort bucket MUST match `combined_finding_key`'s grouping
        // dimensions (language, group_id, flow id, sink class + site)
        // so source-preference tiebreakers decide the primary source
        // only among findings that share the same concrete evidence.
        // Collapsing different flow ids can stitch together a source
        // from one member with a taint_path from another.
        let bucket_a_args = sink_tainted_args_group_key(&a.finding.sink);
        let bucket_b_args = sink_tainted_args_group_key(&b.finding.sink);
        let bucket_a = (
            &a.finding.language,
            a.finding.group_id.as_deref().unwrap_or(""),
            a.finding.representative_flow_id.as_deref().unwrap_or(""),
            &a.finding.sink.file,
            a.finding.sink.line,
            sink_group_class(&a.finding.sink),
            a.finding.sink.text.as_str(),
            bucket_a_args.as_str(),
        );
        let bucket_b = (
            &b.finding.language,
            b.finding.group_id.as_deref().unwrap_or(""),
            b.finding.representative_flow_id.as_deref().unwrap_or(""),
            &b.finding.sink.file,
            b.finding.sink.line,
            sink_group_class(&b.finding.sink),
            b.finding.sink.text.as_str(),
            bucket_b_args.as_str(),
        );
        bucket_a
            .cmp(&bucket_b)
            .then_with(|| {
                source_preference_rank_for_sink(&a.finding.source, Some(&a.finding.sink)).cmp(
                    &source_preference_rank_for_sink(&b.finding.source, Some(&b.finding.sink)),
                )
            })
            .then_with(|| {
                source_specificity_rank(&a.finding.source).cmp(&source_specificity_rank(&b.finding.source))
            })
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
        let member_id = item.finding.finding_id.clone();
        bonsai_diagnostics::debug_log!(
            "find-group",
            "  finding {} src={} sink={}@{}:{} -> key={:?}",
            member_id,
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
            merge_finding_into_group(&mut groups[idx], item.finding, member_id);
            continue;
        }
        let idx = groups.len();
        index.insert(key, idx);
        groups.push(CombinedFindingWithChain {
            finding: item.finding,
            chain_funcs: item.chain_funcs,
            additional_sources: Vec::new(),
            additional_sinks: Vec::new(),
            member_finding_ids: Vec::new(),
        });
    }

    for group in &mut groups {
        finalize_combined_finding(group);
    }
    groups
}

fn combined_finding_key(item: &FindingWithChain) -> String {
    let f = &item.finding;
    let group = f.group_id.as_deref().unwrap_or("");
    let sink_class = sink_group_class(&f.sink);
    let tainted_args = sink_tainted_args_group_key(&f.sink);
    // Key on (language, group_id, flow id, SINK CLASS + SITE). Sink site =
    // file + line + sink text + tainted-arg evidence; sink class is
    // the rule tag/category, falling back to rule id for unclassified
    // rules. This keeps different vulnerability classes separate at
    // the same line while collapsing alias rules that describe the
    // same semantic edge (`cursor.execute`, abbreviated cursor, typed
    // cursor) into one finding.
    //
    // The sink site is what distinguishes genuinely separate findings
    // that happen to share a `group_id`: structurally identical flows
    // in different files hash to the same group tokens, so group_id
    // alone would wrongly collapse them into one row.
    //
    // Key on `representative_flow_id` even when a group id exists.
    // `group_id` intentionally collapses shared tails for grouped
    // presentation, but the representative taint path and source line
    // must describe the same concrete source-to-sink evidence. Without
    // the flow id here, two sources that reach the same sink through a
    // shared tail can produce one mixed row whose source belongs to one
    // member and whose `taint_path` belongs to another.
    //
    // Source is omitted on purpose — co-tainted sources reaching the
    // same sink site fold into the primary's `additional_sources` (this
    // is "combine findings by source flow").
    if !group.is_empty() {
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            f.language,
            group,
            f.representative_flow_id.as_deref().unwrap_or(""),
            f.sink.file,
            f.sink.line,
            sink_class,
            f.sink.text,
            tainted_args
        )
    } else {
        // No group id to anchor on — fall back to the chain + flow id so
        // genuinely distinct flows don't collapse together.
        let chain = f.chain_display.join("\0");
        format!(
            "{}\0\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            f.language,
            chain,
            f.representative_flow_id.as_deref().unwrap_or(""),
            f.sink.file,
            f.sink.line,
            sink_class,
            f.sink.text,
            tainted_args
        )
    }
}

fn extend_java_mdc_context_logger_findings(
    findings: &mut Vec<FindingWithChain>,
    sink_hits: &[RuleMatch],
    pack: &Rulepack,
    ws: &Workspace,
) {
    const MDC_PUT_RULE: &str = "java.log_injection.mdc_put";
    const MDC_CONTEXT_LOGGER_RULE: &str = "java.log_injection.mdc_context_logger_info";

    let Some(sink_rule) = pack.find_rule_by_id(MDC_CONTEXT_LOGGER_RULE) else {
        return;
    };
    let logger_sinks: Vec<&RuleMatch> = sink_hits
        .iter()
        .filter(|hit| hit.rule_id == MDC_CONTEXT_LOGGER_RULE && hit.language == "java")
        .collect();
    if logger_sinks.is_empty() {
        return;
    }

    let mdc_flows: Vec<FindingWithChain> = findings
        .iter()
        .filter(|item| {
            item.finding.language == "java"
                && item.finding.sink.rule_id == MDC_PUT_RULE
                && item.finding.status == FindingStatus::Unsanitized
        })
        .cloned()
        .collect();
    if mdc_flows.is_empty() {
        return;
    }

    let mut existing_ids: AHashSet<String> = findings
        .iter()
        .map(|item| item.finding.finding_id.clone())
        .collect();
    let mut consumed_mdc_finding_ids: AHashSet<String> = AHashSet::new();
    for mdc_flow in mdc_flows {
        let mut emitted_for_mdc_flow = false;
        for logger_sink in &logger_sinks {
            let mut sink_match = FindingMatch::from_rule_match(logger_sink, sink_rule);
            sink_match.tainted_args.push(TaintedArgInfo {
                index: usize::MAX,
                value_text: "MDC context".to_string(),
            });

            let mut chain_display = mdc_flow.finding.chain_display.clone();
            if let Some(sink_fn) = logger_sink.enclosing_fn.as_ref() {
                if !chain_display.iter().any(|name| name == sink_fn) {
                    chain_display.push(sink_fn.clone());
                }
            }

            let mut chain_funcs = mdc_flow.chain_funcs.clone();
            if let Some(sink_func) = func_id_for_match(ws, logger_sink) {
                if !chain_funcs.contains(&sink_func) {
                    chain_funcs.push(sink_func);
                }
            }

            let mut taint_path = mdc_flow.finding.taint_path.clone();
            taint_path.push(TaintPropagationStep {
                caller: logger_sink
                    .enclosing_fn
                    .clone()
                    .unwrap_or_else(|| "<logger>".to_string()),
                callee: logger_sink.match_text.clone(),
                file: logger_sink.file.clone(),
                line: logger_sink.line,
                column: logger_sink.column,
                tainted_args: vec![TaintPropagationArg {
                    index: usize::MAX,
                    value_text: "MDC context".to_string(),
                    param_name: "mdc".to_string(),
                }],
            });

            let group_id = group_id_for_taint_path(&chain_display, &taint_path);
            let flow_id = flow_id_for_taint_path(&chain_display, &taint_path);
            let source_identity = finding_match_identity_token(&mdc_flow.finding.source);
            let sink_identity = finding_match_identity_token(&sink_match);
            let finding_id = compute_finding_id(
                &source_identity,
                &sink_identity,
                &group_id,
                &mdc_flow.finding.language,
            );
            if !existing_ids.insert(finding_id.clone()) {
                continue;
            }

            let root = ws.db().workspace_root();
            let from_test = path_is_test_file_with_root(root.as_deref(), &mdc_flow.finding.source.file)
                || path_is_test_file_with_root(root.as_deref(), &sink_match.file)
                || taint_path
                    .iter()
                    .any(|step| path_is_test_file_with_root(root.as_deref(), &step.file));

            findings.push(FindingWithChain {
                finding: Finding {
                    finding_id,
                    language: mdc_flow.finding.language.clone(),
                    source: mdc_flow.finding.source.clone(),
                    sink: sink_match,
                    sanitizers_seen: mdc_flow.finding.sanitizers_seen.clone(),
                    group_id: Some(group_id),
                    representative_flow_id: Some(flow_id),
                    analysis_complete: mdc_flow.finding.analysis_complete,
                    analysis_incomplete_reasons: mdc_flow.finding.analysis_incomplete_reasons.clone(),
                    chain_display,
                    taint_path,
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
            emitted_for_mdc_flow = true;
        }
        if emitted_for_mdc_flow {
            consumed_mdc_finding_ids.insert(mdc_flow.finding.finding_id);
        }
    }
    if !consumed_mdc_finding_ids.is_empty() {
        findings.retain(|item| !consumed_mdc_finding_ids.contains(&item.finding.finding_id));
    }
}

fn sink_group_class(sink: &FindingMatch) -> &str {
    sink.tag
        .as_deref()
        .or(sink.category.as_deref())
        .unwrap_or(sink.rule_id.as_str())
}

fn sink_tainted_args_group_key(sink: &FindingMatch) -> String {
    let mut args = sink
        .tainted_args
        .iter()
        .map(|arg| format!("{}={}", arg.index, arg.value_text.trim()))
        .collect::<Vec<_>>();
    args.sort();
    args.join("|")
}

fn merge_finding_into_group(group: &mut CombinedFindingWithChain, incoming: Finding, member_id: String) {
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
    merge_finding_matches(&mut group.finding.sanitizers_seen, incoming.sanitizers_seen);
    merge_analysis_completeness(
        &mut group.finding.analysis_complete,
        &mut group.finding.analysis_incomplete_reasons,
        incoming.analysis_complete,
        incoming.analysis_incomplete_reasons,
    );
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
    let mut sinks = Vec::with_capacity(1 + group.additional_sinks.len());
    sinks.push(group.finding.sink.clone());
    sinks.extend(group.additional_sinks.iter().cloned());
    sinks.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| (a.file.as_str(), a.line, a.column).cmp(&(b.file.as_str(), b.line, b.column)))
    });
    group.finding.sink = sinks[0].clone();
    group.additional_sinks = sinks.into_iter().skip(1).collect();

    // The primary source stays pinned to the first-seen bucket member.
    // `combine_findings_by_source_flow` pre-sorts findings so the preferred
    // source (concrete rulepack sources rank ahead of inferred entry-point
    // placeholders via `source_preference_rank_for_sink`) is seen first, and
    // `merge_finding_into_group` retains that same member's flow evidence
    // (`taint_path`, `representative_flow_id`, `chain_display`). Re-deriving a
    // different primary here — as an earlier version did by re-ranking every
    // co-tainted source against the group's severity-max sink — can promote a
    // source whose evidence was NOT retained, so the reported source would
    // never appear on the reported taint path (the exact "mixed row" the
    // grouping key is designed to prevent). Keep the primary and only surface
    // co-tainted sources that alias the primary's exact call site, in a stable
    // display order.
    let primary_source = group.finding.source.clone();
    let mut additional_sources: Vec<FindingMatch> = std::mem::take(&mut group.additional_sources)
        .into_iter()
        .filter(|source| same_source_location(&primary_source, source))
        .collect();
    additional_sources.sort_by(|a, b| {
        (a.file.as_str(), a.line, a.column)
            .cmp(&(b.file.as_str(), b.line, b.column))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    group.additional_sources = additional_sources;

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

/// Append finding matches from `src` into `dst`, deduping by
/// `(rule_id, file, line)`. Column is intentionally omitted — same
/// rule + same line means the same logical site even when the
/// adapter reports a slightly different column.
fn merge_finding_matches(dst: &mut Vec<FindingMatch>, src: Vec<FindingMatch>) {
    for item in src {
        if !dst.iter().any(|existing| {
            existing.rule_id == item.rule_id && existing.file == item.file && existing.line == item.line
        }) {
            dst.push(item);
        }
    }
}

/// Build chain-aware findings: source rule matches → propagated taint
/// → sink rule matches → assembled findings with stable IDs.
///
/// ## Pipeline phases
///
/// 1. **Resolve matcher hits to FuncIds by span** — per-FuncId
///    sanitizer and sink attribution avoids cross-bridging same-named
///    functions or methods in the same file.
/// 2. **Group sanitizers + sinks by enclosing FuncId** — one
///    `Vec<RuleMatch>` per function, ready for chain-hop attribution.
/// 3. **Per-source seeding** (`source_work` building) — select
///    source value nodes from the per-function value-flow graph,
///    then augment with strict event-walk targets via
///    `source_seed_set` + `collect_source_seed_targets`.
///    `security_text_matches_source_strict` prevents receiver
///    substrings from tainting sibling members.
/// 4. **Source-bearing helpers** (`source_returning_indices`) —
///    via `source_seed_reaches_return`, mark helpers whose return is
///    proven to carry source-derived data so the inter pass can
///    propagate `var = helper()` taint.
/// 5. **Run interprocedural taint per source** — `exact_source_seed_graph`
///    drives `interprocedural_taint_to_completion_with_caches` until
///    the per-source semantic worklist drains.
/// 6. **Sink matching** — iterate `tainted_calls`, prefer
///    span-equality match for multi-sink-in-same-fn attribution,
///    apply sink-rule constraints with single-call `InterTaintView`.
/// 7. **Chain assembly** — use propagation lineage IDs recorded by
///    the taint engine. If lineage evidence is missing, skip the
///    finding rather than fabricating a call-graph-only path. Precision
///    is met across the chosen edges, then `flow_id` / `group_id`
///    include concrete call sites. Sanitizer attachment by chain hop
///    with data-flow gate
///    (`sanitizer_call_overlaps_tainted_call` or a sanitizer nested
///    directly inside a tainted sink argument).
/// 8. **Trust-aware severity** — `local`/`inferred` source tier
///    demotes severity one level (Critical → High, etc.).
///
/// `combine_findings_by_source_flow` is the post-pipeline that groups
/// by `(language, group_id, flow_id, chain_display, sink_rule_id)`,
/// merges severity/tag/CWE/sanitizers/status, and recomputes
/// `finding_id` over the combined source/sink token sets.
#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
fn build_findings_chain_aware<F>(
    ws: &Workspace,
    source_hits: &[RuleMatch],
    sinks: &[RuleMatch],
    sanitizers: &[RuleMatch],
    pack: &Rulepack,
    interprocedural_budget: Option<u32>,
    intra_worklist_cap: Option<u32>,
    max_precision: Option<Precision>,
    taint_graph_resident_cache_entries: Option<usize>,
    factory_returns: &crate::matcher::FactoryReturns,
    on_progress: &mut F,
) -> Vec<FindingWithChain>
where
    F: FnMut(AnalysisProgress),
{
    // ---- Phase 1: resolve rule matches to enclosing FuncIds ----
    let global = ws.db().global_index();
    // Run-scoped memo for the workspace-wide receiver→base-type map. Sink
    // constraint re-checks (`rule_match_passes_constraints_with_taint_view`)
    // run once per candidate; without this the whole-workspace scan that
    // feeds `receiver_type_in` constraints would be rebuilt per candidate.
    // `OnceLock` is `Sync`, so the parallel source-group workers below share
    // one lazily-built map. Only populated if some sink rule needs it.
    let receiver_base_map_cell: OnceLock<AHashMap<String, Vec<String>>> = OnceLock::new();
    // Use the concrete source span to resolve each matcher hit to the
    // declaration that contains it. Name-only keys (`file + get`) can
    // conflate unrelated methods such as `Handler.get` and
    // `Helper.get`, then attach a source in one class to a sink in the
    // other.
    let mut san_by_func: AHashMap<FuncId, Vec<&RuleMatch>> = AHashMap::new();
    for s in sanitizers {
        if let Some(fid) = func_id_for_match(ws, s) {
            san_by_func.entry(fid).or_default().push(s);
        }
    }
    let mut sink_by_func: AHashMap<FuncId, Vec<&RuleMatch>> = AHashMap::new();
    for snk in sinks {
        if let Some(sink_func_id) = func_id_for_match(ws, snk) {
            sink_by_func.entry(sink_func_id).or_default().push(snk);
        }
    }
    // Workspace-wide source-seeded graph index. The resident cache is
    // bounded and guarded by a rule/config fingerprint, so reuse
    // cannot keep stale graphs alive across rulepack or precision
    // changes and cannot grow without limit on large scans. Disk
    // persistence is best-effort and default-on so repeated CLI runs
    // can hydrate exact graphs from the sidecar instead of replaying
    // the same taint solve. Set `BONSAI_TAINT_GRAPH_PERSIST=0` to
    // disable the performance artifact for disk-constrained runs.
    //
    // Prepared BEFORE the no-work early return below: the cache
    // decision (scoped workspaces skip the shared sidecar; unscoped
    // runs hydrate it) is made per-invocation regardless of whether
    // any source/sink pairs exist, and callers observe it through the
    // `taint-cache` note — a scoped run must always be able to prove
    // it did not touch the shared sidecar.
    let workspace_taint_index = ws.taint_index();
    if let Some(resident_cap) = taint_graph_resident_cache_entries {
        workspace_taint_index.set_resident_capacity(resident_cap);
    }
    let taint_graph_fingerprint =
        taint_cache::config_fingerprint(pack, "taint-analysis", max_precision);
    let cache_report = taint_cache::prepare_workspace_cache(ws, "taint-analysis", taint_graph_fingerprint);
    let cache_persist_started = cache_report.persist_started;
    on_progress(AnalysisProgress::Note {
        label: "taint-cache",
        detail: cache_report.detail(),
    });
    if source_hits.is_empty() || sink_by_func.is_empty() {
        // No source/sink work will run, but `prepare_workspace_cache`
        // may have opened the sidecar write-through — close it so the
        // temp file never dangles.
        if cache_persist_started {
            let _ = taint_cache::finish_workspace_cache(ws);
        }
        return Vec::new();
    }
    let mut out = Vec::new();
    // Materialise per-source seed names in source order. The exact
    // graph builder receives the source span separately and resolves
    // concrete IDG seed nodes from that anchor, so broad scans no
    // longer need to build a full seed-free value-flow graph for every
    // source-bearing function before the source-seeded graph phase.
    struct SourceForFunction<'a> {
        index: usize,
        src: &'a RuleMatch,
    }
    let mut best_sources: AHashMap<SourceMatchDedupeKey, SourceMatchDedupeValue<'_>> = AHashMap::new();
    for (idx, src) in source_hits.iter().enumerate() {
        let Some(src_func_id) = func_id_for_match(ws, src) else {
            continue;
        };
        let specificity = global
            .decl_of(SymbolId::new(src_func_id.raw()))
            .map(|decl| decl.span.len())
            .unwrap_or(u64::MAX);
        let key = (
            src.rule_id.clone(),
            src.file.clone(),
            src.span.start,
            src.span.end,
            src.match_text.clone(),
        );
        match best_sources.get_mut(&key) {
            Some(existing) if specificity < existing.3 || (specificity == existing.3 && idx < existing.0) => {
                *existing = (idx, src, src_func_id, specificity);
            }
            Some(_) => {}
            None => {
                best_sources.insert(key, (idx, src, src_func_id, specificity));
            }
        }
    }
    let mut sources_by_func: AHashMap<FuncId, Vec<SourceForFunction<'_>>> = AHashMap::new();
    for (_, (idx, src, src_func_id, _)) in best_sources {
        sources_by_func
            .entry(src_func_id)
            .or_default()
            .push(SourceForFunction { index: idx, src });
    }
    let mut sources_by_func_sorted: Vec<(FuncId, Vec<SourceForFunction<'_>>)> =
        sources_by_func.into_iter().collect();
    sources_by_func_sorted
        .sort_by_key(|(_, sources)| sources.first().map(|source| source.index).unwrap_or(usize::MAX));
    let mut indexed_source_entries: Vec<(usize, (&RuleMatch, FuncId, TokenSet))> = Vec::new();
    for (src_func_id, sources) in sources_by_func_sorted {
        let Some(src_decl) = global.decl_of(SymbolId::new(src_func_id.raw())) else {
            continue;
        };
        for source in sources {
            let seeds = source_seed_set(pack, source.src, src_decl, None);
            let anchor = source_anchor_for_rule_match(pack, source.src);
            if seeds.is_empty() && anchor.is_none() {
                continue;
            }
            indexed_source_entries.push((source.index, (source.src, src_func_id, seeds)));
        }
    }
    indexed_source_entries.sort_by_key(|(idx, _)| *idx);
    let source_entries: Vec<(&RuleMatch, FuncId, TokenSet)> = indexed_source_entries
        .into_iter()
        .map(|(_, entry)| entry)
        .collect();
    let mut source_work: Vec<(&RuleMatch, FuncId, TokenSet)> = Vec::with_capacity(source_entries.len());
    let mut source_groups: AHashMap<FuncId, Vec<usize>> = AHashMap::new();
    for (src, src_func_id, seeds) in source_entries {
        let idx = source_work.len();
        source_work.push((src, src_func_id, seeds));
        source_groups.entry(src_func_id).or_default().push(idx);
    }
    let transfer_languages: AHashSet<String> = source_hits
        .iter()
        .chain(sinks.iter())
        .chain(sanitizers.iter())
        .map(|rule_match| rule_match.language.clone())
        .collect();
    let receiver_state_propagations =
        receiver_state_propagations_from_rulepack_for_languages(pack, &transfer_languages);
    // IDG closures already follow `callee.Return -> caller.CallRet`
    // edges and then continue through caller-side flow. The legacy
    // engine needed a separate "source reaches return" prepass to
    // schedule callers with synthetic empty seeds; doing that in the
    // IDG path is both redundant and imprecise because empty seeds
    // fall back to all caller params. Keep the phase boundary for
    // progress/API stability, but make it a no-op.
    on_progress(AnalysisProgress::PhaseStarted {
        label: "checking source returns",
        total: 0,
    });
    use rayon::prelude::*;
    on_progress(AnalysisProgress::PhaseFinished);

    let config = InterTaintConfig {
        sanitizers: TokenSet::default(),
        budget: interprocedural_budget.unwrap_or_else(|| InterTaintConfig::default().budget),
        intra_worklist_cap,
        source_bearing_functions: AHashSet::default(),
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
        receiver_state_propagations,
        max_edge_precision: max_precision,
        ..Default::default()
    };
    let mut source_func_ids: Vec<FuncId> = source_groups.keys().copied().collect();
    source_func_ids.sort_by_key(|func| func.raw());
    let source_callback_targets =
        configured_source_callback_targets_by_source(&source_work, pack, global.as_ref());
    let mut source_func_ids_for_graph = source_func_ids.clone();
    source_func_ids_for_graph.extend(
        source_callback_targets
            .values()
            .flat_map(|targets| targets.iter().copied()),
    );
    source_func_ids_for_graph.sort_by_key(|func| func.raw());
    source_func_ids_for_graph.dedup();
    let mut sink_func_ids: Vec<FuncId> = sink_by_func.keys().copied().collect();
    sink_func_ids.sort_by_key(|func| func.raw());
    on_progress(AnalysisProgress::PhaseStarted {
        label: "building source-reachable callgraph",
        total: 0,
    });
    let reachable_call_graph = ws.source_reachable_resolved_call_graph(
        &source_func_ids_for_graph,
        &sink_func_ids,
        config.max_edge_precision,
    );
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "semantic graph scope source_funcs={} sink_funcs={} reached_sinks={} funcs={} files={}",
        source_func_ids.len(),
        sink_func_ids.len(),
        reachable_call_graph.reached_targets,
        reachable_call_graph.funcs.len(),
        reachable_call_graph.files.len()
    );
    if reachable_call_graph.funcs.len() <= 64 {
        let global = ws.db().global_index();
        let names: Vec<String> = reachable_call_graph
            .funcs
            .iter()
            .filter_map(|func| {
                global
                    .decl_of(bonsai_common::SymbolId::new(func.raw()))
                    .map(|decl| format!("{}:{:?}", decl.name, decl.kind))
            })
            .collect();
        bonsai_diagnostics::debug_log!("security-phase", "semantic graph funcs={}", names.join(", "));
    }
    on_progress(AnalysisProgress::PhaseFinished);

    let chain_call_graph = reachable_call_graph.graph.clone();
    let sink_func_set: AHashSet<FuncId> = sink_by_func.keys().copied().collect();
    let source_sink_prefilter_enabled = !source_work.is_empty() && !sink_func_set.is_empty();
    // AHashMap iteration order is hash-randomized per process. Sort
    // by FuncId.raw() so the per-source-group analysis order and
    // resulting finding fingerprints are stable across runs.
    let mut source_groups_sorted: Vec<(FuncId, Vec<usize>)> =
        source_groups.iter().map(|(k, v)| (*k, v.clone())).collect();
    source_groups_sorted.sort_by_key(|(k, _)| k.raw());
    let scheduling_total = source_groups_sorted
        .iter()
        .map(|(_, indices)| indices.len() as u64)
        .sum();

    let mut coarse_scope_funcs: AHashSet<FuncId> = AHashSet::new();
    let mut coarse_corridors_by_func: AHashMap<FuncId, SourceSinkCorridor> = AHashMap::new();
    if source_sink_prefilter_enabled {
        for (src_func_id, indices) in &source_groups_sorted {
            if indices.is_empty() {
                continue;
            }
            if let Some(mut corridor) = callgraph_source_sink_corridor(
                *src_func_id,
                &sink_func_set,
                global.as_ref(),
                chain_call_graph.as_ref(),
                config.max_edge_precision,
            ) {
                corridor.lineage_funcs.insert(*src_func_id);
                extend_corridor_with_summary_dependency_support(
                    &mut corridor,
                    global.as_ref(),
                    chain_call_graph.as_ref(),
                    config.max_edge_precision,
                );
                coarse_scope_funcs.extend(corridor.lineage_funcs.iter().copied());
                coarse_corridors_by_func.insert(*src_func_id, corridor);
            }
        }
        let callback_scope_funcs = merge_configured_source_callback_corridors(
            &mut coarse_corridors_by_func,
            &source_callback_targets,
            &sink_func_set,
            global.as_ref(),
            chain_call_graph.as_ref(),
            config.max_edge_precision,
        );
        coarse_scope_funcs.extend(callback_scope_funcs);
    }
    let (semantic_files, semantic_funcs): (Vec<FileId>, Vec<FuncId>) = if coarse_scope_funcs.is_empty() {
        (
            reachable_call_graph.files.clone(),
            reachable_call_graph.funcs.clone(),
        )
    } else {
        let mut funcs: Vec<FuncId> = coarse_scope_funcs.into_iter().collect();
        funcs.sort_by_key(|func| func.raw());
        funcs.dedup();
        let mut files: Vec<FileId> = funcs
            .iter()
            .filter_map(|func| global.declaring_file(SymbolId::new(func.raw())))
            .collect();
        files.sort_by_key(|file| file.raw());
        files.dedup();
        (files, funcs)
    };
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "semantic graph idg scope funcs={} files={} full_funcs={} full_files={} coarse_source_groups={}",
        semantic_funcs.len(),
        semantic_files.len(),
        reachable_call_graph.funcs.len(),
        reachable_call_graph.files.len(),
        coarse_corridors_by_func.len()
    );

    let use_batched_scoped_idg = source_sink_prefilter_enabled && semantic_funcs.len() > 100_000;
    let idg = if use_batched_scoped_idg {
        on_progress(AnalysisProgress::PhaseStarted {
            label: "planning scoped semantic graph batches",
            total: 0,
        });
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "semantic graph batching enabled funcs={} files={} source_groups={}",
            semantic_funcs.len(),
            semantic_files.len(),
            coarse_corridors_by_func.len()
        );
        on_progress(AnalysisProgress::PhaseFinished);
        None
    } else {
        on_progress(AnalysisProgress::PhaseStarted {
            label: "building scoped semantic graph",
            total: 0,
        });
        let service = seed_idg_service_for_rulepack_for_files(
            ws,
            pack,
            &transfer_languages,
            &semantic_files,
            &semantic_funcs,
            chain_call_graph.as_ref(),
        );
        on_progress(AnalysisProgress::PhaseFinished);
        Some(service)
    };
    let sink_target_nodes = if source_sink_prefilter_enabled {
        let semantic_func_set: AHashSet<FuncId> = semantic_funcs.iter().copied().collect();
        let semantic_sink_func_set: AHashSet<FuncId> =
            sink_func_set.intersection(&semantic_func_set).copied().collect();
        idg.as_ref().map(|service| {
            sink_target_nodes_for_funcs(service.as_ref(), pack, &sink_by_func, &semantic_sink_func_set)
        })
    } else {
        None
    };
    let sink_match_count: usize = if source_sink_prefilter_enabled {
        let semantic_func_set: AHashSet<FuncId> = semantic_funcs.iter().copied().collect();
        sink_func_set
            .intersection(&semantic_func_set)
            .filter_map(|func| sink_by_func.get(func))
            .map(Vec::len)
            .sum()
    } else {
        sink_by_func.values().map(Vec::len).sum()
    };
    let sink_target_nodes_for_schedule = sink_target_nodes
        .as_ref()
        .filter(|targets| targets.complete && !targets.nodes.is_empty())
        .map(|targets| targets.nodes.as_slice());
    let use_coarse_source_sink_schedule =
        use_batched_scoped_idg || (transfer_languages.contains("java") && semantic_funcs.len() > 1_000);
    let target_node_graph_cut_enabled = sink_target_nodes
        .as_ref()
        .is_some_and(|targets| targets.complete && !targets.nodes.is_empty());
    if let Some(targets) = sink_target_nodes.as_ref() {
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "sink target nodes nodes={} sink_matches={} complete={} unresolved_funcs={} schedule_node_cut={} graph_node_cut={}",
            targets.nodes.len(),
            sink_match_count,
            targets.complete,
            targets.unresolved_funcs.len(),
            sink_target_nodes_for_schedule.is_some(),
            target_node_graph_cut_enabled
        );
    }
    let sink_target_nodes_for_graph: Option<&[bonsai_idg::WsNodeId]> = if target_node_graph_cut_enabled {
        sink_target_nodes.as_ref().map(|targets| targets.nodes.as_slice())
    } else {
        None
    };
    let taint_caches = ws.inter_taint_caches();
    taint_caches.seed_resolved_call_graph(chain_call_graph.as_ref());
    // (Workspace taint-graph index + sidecar prepare happen at the top
    // of this function, before the no-work early return.)
    if source_sink_prefilter_enabled {
        on_progress(AnalysisProgress::PhaseStarted {
            label: "building source-sink reachability",
            total: scheduling_total,
        });
    }

    struct ScheduledSourceGroup {
        src_func_id: FuncId,
        indices: Vec<usize>,
        corridor: SourceSinkCorridor,
    }

    let debug_taint_phase = bonsai_diagnostics::debug::is_enabled("security-taint");
    let mut scheduled_source_groups = Vec::new();
    for (src_func_id, indices) in source_groups_sorted {
        let mut filtered_indices = Vec::with_capacity(indices.len());
        let mut group_corridor = SourceSinkCorridor::default();
        for idx in indices.iter().copied() {
            let corridor = if use_coarse_source_sink_schedule {
                coarse_corridors_by_func.get(&src_func_id).cloned()
            } else if let (Some(service), Some(target_nodes)) = (idg.as_ref(), sink_target_nodes_for_schedule)
            {
                let coarse_corridor = coarse_corridors_by_func.get(&src_func_id);
                source_index_sink_corridor(
                    idx,
                    &source_work,
                    pack,
                    &config,
                    global.as_ref(),
                    service.as_ref(),
                    target_nodes,
                    sink_target_nodes.as_ref().is_none_or(|targets| targets.complete),
                    coarse_corridor,
                )
            } else {
                coarse_corridors_by_func.get(&src_func_id).cloned()
            };
            if let Some(corridor) = corridor {
                filtered_indices.push(idx);
                group_corridor.extend(corridor);
            }
            if source_sink_prefilter_enabled {
                on_progress(AnalysisProgress::PhaseTicked);
            }
        }
        if filtered_indices.is_empty() {
            if debug_taint_phase {
                let name = global
                    .decl_of(SymbolId::new(src_func_id.raw()))
                    .map(|decl| decl.name.clone())
                    .unwrap_or_default();
                bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "group func={}({}) sources={} skipped=no_source_to_sink_node_cut",
                    name,
                    src_func_id.raw(),
                    indices.len()
                );
            }
            continue;
        }
        if let Some(coarse_corridor) = coarse_corridors_by_func.get(&src_func_id).cloned() {
            group_corridor.extend(coarse_corridor);
        }
        group_corridor.lineage_funcs.insert(src_func_id);
        if !use_coarse_source_sink_schedule {
            extend_corridor_with_summary_dependency_support(
                &mut group_corridor,
                global.as_ref(),
                chain_call_graph.as_ref(),
                config.max_edge_precision,
            );
        }
        scheduled_source_groups.push(ScheduledSourceGroup {
            src_func_id,
            indices: filtered_indices,
            corridor: group_corridor,
        });
    }
    if source_sink_prefilter_enabled {
        on_progress(AnalysisProgress::PhaseFinished);
    }

    on_progress(AnalysisProgress::PhaseStarted {
        label: "scheduling taint sources",
        total: scheduling_total,
    });
    for _ in 0..scheduling_total {
        on_progress(AnalysisProgress::PhaseTicked);
    }
    on_progress(AnalysisProgress::PhaseFinished);

    bonsai_diagnostics::debug_log!(
        "security-phase",
        "source groups scheduled total={} filtered={} prefilter_enabled={} reachable_funcs={}",
        source_groups.len(),
        scheduled_source_groups.len(),
        source_sink_prefilter_enabled,
        scheduled_source_groups
            .iter()
            .flat_map(|group| group.corridor.lineage_funcs.iter().copied())
            .collect::<AHashSet<_>>()
            .len()
    );
    let reachable_funcs = scheduled_source_groups
        .iter()
        .flat_map(|group| group.corridor.lineage_funcs.iter().copied())
        .collect::<AHashSet<_>>()
        .len();
    on_progress(AnalysisProgress::Note {
        label: "scope",
        detail: format!(
            "taint-analysis source_groups={} scheduled_groups={} reachable_funcs={} source_sink_prefilter={}",
            source_groups.len(),
            scheduled_source_groups.len(),
            reachable_funcs,
            source_sink_prefilter_enabled
        ),
    });
    let total_groups = scheduled_source_groups.len();
    on_progress(AnalysisProgress::PhaseStarted {
        label: "building taint chains",
        total: total_groups as u64,
    });
    let build_source_group = |group: &ScheduledSourceGroup, idg: &bonsai_idg::IdgQueryService| {
        let src_func_id = group.src_func_id;
        let indices = &group.indices;
        let group_started = debug_taint_phase.then(Instant::now);
        let mut graph_nanos = 0u128;
        let mut attribution_nanos = 0u128;
        let mut graph_builds = 0usize;
        let mut group_graph_hits = 0usize;
        let mut workspace_graph_hits = 0usize;
        let mut empty_graphs = 0usize;
        let mut tainted_calls_seen = 0usize;
        let mut sink_candidate_checks = 0usize;
        let mut sink_matches = 0usize;
        let mut lineage_misses = 0usize;
        let mut group_out: Vec<FindingWithChain> = Vec::new();
        let group_target_nodes_owned: Option<Vec<bonsai_idg::WsNodeId>> = sink_target_nodes_for_graph
            .and_then(|global_targets| {
                if !group.corridor.target_nodes.is_empty() {
                    return Some(group.corridor.target_nodes.clone());
                }
                let mut nodes: Vec<bonsai_idg::WsNodeId> = global_targets
                    .iter()
                    .copied()
                    .filter(|node| {
                        idg.resolve_point(*node)
                            .is_some_and(|point| group.corridor.terminal_sinks.contains(&point.func))
                    })
                    .collect();
                nodes.sort();
                nodes.dedup();
                (!nodes.is_empty()).then_some(nodes)
            });
        let group_target_nodes = group_target_nodes_owned.as_deref();
        let unresolved_sink_func_targets: Option<AHashSet<FuncId>> = group_target_nodes.and_then(|_| {
            sink_target_nodes.as_ref().and_then(|targets| {
                let unresolved: AHashSet<FuncId> = group
                    .corridor
                    .terminal_sinks
                    .intersection(&targets.unresolved_funcs)
                    .copied()
                    .collect();
                (!unresolved.is_empty()).then_some(unresolved)
            })
        });
        let group_sink_func_targets = if group_target_nodes.is_some() {
            unresolved_sink_func_targets.as_ref()
        } else {
            Some(&group.corridor.terminal_sinks)
        };
        let group_lineage_func_targets = Some(&group.corridor.lineage_funcs);
        if debug_taint_phase {
            let mut names: Vec<String> = group
                .corridor
                .lineage_funcs
                .iter()
                .filter_map(|func| {
                    global
                        .decl_of(SymbolId::new(func.raw()))
                        .map(|decl| format!("{}({})", decl.name, func.raw()))
                })
                .collect();
            names.sort();
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "group func={} lineage_funcs={:?}",
                src_func_id.raw(),
                names
            );
        }
        let mut emitted_for_source_sink_flow: AHashSet<(usize, String, u32, u64, u64, Option<u64>)> =
            AHashSet::new();
        // Bounded L1 for this one source function. Several
        // source-rule matches in the same function can collapse
        // to the same exact seed shape; computing that graph
        // once per group avoids duplicated exact work without
        // retaining every source graph for the whole workspace.
        let mut group_graphs: AHashMap<Vec<String>, Arc<EntryTaintGraph>> = AHashMap::new();
        for &idx in indices {
            let (src, _, seeds) = &source_work[idx];
            let output_arg_names = global
                .decl_of(SymbolId::new(src_func_id.raw()))
                .map(|d| output_arg_names_for_match(pack, src, d))
                .unwrap_or_default();
            let anchor = source_anchor_for_rule_match(pack, src);
            let mut seed_key = effective_source_seed_key(
                src_func_id,
                seeds,
                anchor,
                &output_arg_names,
                global.as_ref(),
                idg,
            );
            append_taint_target_key(&mut seed_key, "target_funcs", group_sink_func_targets);
            append_taint_target_key(&mut seed_key, "lineage_funcs", group_lineage_func_targets);
            append_taint_target_node_key(&mut seed_key, "target_nodes", group_target_nodes);
            let graph_key = (src_func_id, seed_key);
            // Compute the per-`(source_func, seed_shape)` graph
            // exactly. The per-group cache removes duplicate work
            // inside this source function; the workspace cache gives
            // repeat SDK calls bounded reuse across invocations.
            let graph_started = debug_taint_phase.then(Instant::now);
            let graph = if let Some(hit) = group_graphs.get(&graph_key.1) {
                group_graph_hits = group_graph_hits.saturating_add(1);
                hit.clone()
            } else {
                let workspace_hit = if use_batched_scoped_idg {
                    None
                } else {
                    workspace_taint_index.get(src_func_id, &graph_key.1)
                };
                if let Some(hit) = workspace_hit {
                    workspace_graph_hits = workspace_graph_hits.saturating_add(1);
                    group_graphs.insert(graph_key.1.clone(), hit.clone());
                    hit
                } else {
                    graph_builds = graph_builds.saturating_add(1);
                    let graph = Arc::new(exact_source_seed_graph(
                        src_func_id,
                        seeds,
                        &config,
                        ws.db(),
                        taint_caches,
                        idg,
                        anchor,
                        &output_arg_names,
                        group_target_nodes,
                        group_sink_func_targets,
                        group_lineage_func_targets,
                    ));
                    let graph = if use_batched_scoped_idg {
                        graph
                    } else {
                        workspace_taint_index.insert_if_absent(src_func_id, graph_key.1.clone(), graph)
                    };
                    group_graphs.insert(graph_key.1.clone(), graph.clone());
                    graph
                }
            };
            if let Some(started) = graph_started {
                graph_nanos = graph_nanos.saturating_add(started.elapsed().as_nanos());
            }
            if graph.tainted_calls.is_empty() {
                empty_graphs = empty_graphs.saturating_add(1);
                continue;
            }
            tainted_calls_seen = tainted_calls_seen.saturating_add(graph.tainted_calls.len());
            if debug_taint_phase
                && sink_by_func
                    .keys()
                    .all(|func| !graph.tainted_calls.iter().any(|call| call.caller == *func))
            {
                let mut call_sites: Vec<String> = graph
                    .tainted_calls
                    .iter()
                    .take(24)
                    .map(|call| {
                        let caller_name = global
                            .decl_of(SymbolId::new(call.caller.raw()))
                            .map(|decl| decl.name.clone())
                            .unwrap_or_else(|| call.caller.raw().to_string());
                        format!(
                            "{}({})::{}@{}..{} kind={:?} args={:?} recv={:?}",
                            caller_name,
                            call.caller.raw(),
                            call.name,
                            call.call_span.start,
                            call.call_span.end,
                            call.kind,
                            call.tainted_args,
                            call.tainted_receiver
                        )
                    })
                    .collect();
                call_sites.sort();
                bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "graph_has_no_sink_callers source_rule={} src_func={} tainted_calls={} sample={:?}",
                    src.rule_id,
                    src_func_id.raw(),
                    graph.tainted_calls.len(),
                    call_sites
                );
            }
            let unresolved_call_index = GraphUnresolvedCallIndex::new(global.as_ref(), graph.as_ref());
            let attribution_started = debug_taint_phase.then(Instant::now);
            // Span set of every recorded tainted call on this
            // source graph — sanitizer credit pass uses it to
            // require data-flow connectivity rather than mere
            // chain co-occurrence.
            let tainted_call_spans: AHashSet<Span> =
                graph.tainted_calls.iter().map(|c| c.call_span).collect();
            let trace_index = trace_record_index(&graph.call_records);
            let canonical_chain_index =
                CanonicalChainIndex::new(&graph.call_records, chain_call_graph.as_ref());
            for call in &graph.tainted_calls {
                let Some(candidate_sinks) = sink_by_func.get(&call.caller) else {
                    continue;
                };
                let mut cached_evidence: Option<Option<CallEvidence>> = None;
                sink_candidate_checks = sink_candidate_checks.saturating_add(candidate_sinks.len());
                // Multi-sink attribution: when several sinks live in
                // the same function, prefer span-equality over text
                // overlap. If ANY candidate sink shares a span with
                // this call, attribute to span-matches only — text
                // match is a fallback used when no sink overlaps the
                // call's span (e.g. cross-file references). The
                // Strapi `_.template(layout)` / `fs.readFileSync(path)`
                // case is the canonical motivator: previously the same
                // source attached to BOTH because text-matching is
                // loose enough to bridge unrelated calls.
                let any_exact_span_match = candidate_sinks
                    .iter()
                    .any(|snk| snk.language == src.language && snk.span == call.call_span);
                let any_span_match = candidate_sinks
                    .iter()
                    .any(|snk| snk.language == src.language && spans_overlap(call.call_span, snk.span));
                for snk in candidate_sinks {
                    if snk.language != src.language {
                        continue;
                    }
                    if any_exact_span_match {
                        if snk.span != call.call_span {
                            continue;
                        }
                    } else if any_span_match {
                        if !spans_overlap(call.call_span, snk.span) {
                            continue;
                        }
                    } else if !tainted_call_matches_sink(call, snk) {
                        continue;
                    }
                    if !source_can_precede_sink(ws, pack, src, src_func_id, snk, call.caller) {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_rejected_order source_rule={} sink_rule={} src_func={} sink_func={} caller={} call={} source_span={:?} sink_span={:?} call_span={:?}",
                            src.rule_id,
                            snk.rule_id,
                            src_func_id.raw(),
                            func_id_for_match(ws, snk).map(|func| func.raw()).unwrap_or_default(),
                            call.caller.raw(),
                            call.name,
                            src.span,
                            snk.span,
                            call.call_span
                        );
                        continue;
                    }
                    if same_function_clean_overwrite_kills_sink_arg(
                        ws,
                        src_func_id,
                        call.caller,
                        src.span,
                        snk.span,
                        &call.tainted_args,
                        call.tainted_receiver.as_deref(),
                    ) {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_rejected_same_func_clean_overwrite source_rule={} sink_rule={} caller={} call={} span={:?} tainted_args={:?} receiver={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span,
                            call.tainted_args,
                            call.tainted_receiver
                        );
                        continue;
                    }
                    if interprocedural_clean_overwrite_kills_lineage_arg(
                        ws,
                        src_func_id,
                        src.span,
                        &trace_index,
                        call,
                    ) {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_rejected_inter_clean_overwrite source_rule={} sink_rule={} caller={} call={} span={:?} tainted_args={:?} receiver={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span,
                            call.tainted_args,
                            call.tainted_receiver
                        );
                        continue;
                    }
                    sink_matches = sink_matches.saturating_add(1);
                    // Return / Write tainted-call rows are emitted
                    // as evidence that *the function's return slot
                    // / write target* received tainted data — they
                    // don't carry tainted_args because there is no
                    // "argument" to flag, the dataflow happened on
                    // the return expression itself. Skip the
                    // empty-args/receiver guard for those kinds so
                    // a `MatchKind::Return` sink rule (or
                    // `MatchKind::Write`) can still fire on the
                    // span the IDG closure proved tainted.
                    let kind_emits_synthetic_evidence = matches!(
                        call.kind,
                        bonsai_taint::TaintedCallKind::Return | bonsai_taint::TaintedCallKind::Write
                    );
                    if !kind_emits_synthetic_evidence
                        && call.tainted_args.is_empty()
                        && call.tainted_receiver.is_none()
                    {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_dropped_empty_evidence source_rule={} sink_rule={} caller={} call={} span={:?} kind={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span,
                            call.kind
                        );
                        continue;
                    }
                    let Some(sink_rule) = pack.find_rule_by_id(&snk.rule_id) else {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_missing_rule source_rule={} sink_rule={} caller={} call={} span={:?} kind={:?} tainted_args={:?} receiver={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span,
                            call.kind,
                            call.tainted_args,
                            call.tainted_receiver
                        );
                        continue;
                    };
                    if prototype_pollution_sink_is_guarded(ws, sink_rule, snk) {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_guarded source_rule={} sink_rule={} caller={} call={} span={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span
                        );
                        continue;
                    }
                    if !sink_rule.constraints.is_empty() {
                        let current_call_view = std::slice::from_ref(call);
                        let current_call_taint_view = InterTaintView::new(current_call_view);
                        if !rule_match_passes_constraints_with_taint_view(
                            ws,
                            sink_rule,
                            snk,
                            &current_call_taint_view,
                            factory_returns,
                            &receiver_base_map_cell,
                        ) {
                            bonsai_diagnostics::debug_log!(
                                "security-taint",
                                "sink_match_constraint_failed source_rule={} sink_rule={} caller={} call={} span={:?} kind={:?} tainted_args={:?} receiver={:?} constraints={:?}",
                                src.rule_id,
                                snk.rule_id,
                                call.caller.raw(),
                                call.name,
                                call.call_span,
                                call.kind,
                                call.tainted_args,
                                call.tainted_receiver,
                                sink_rule.constraints
                            );
                            continue;
                        }
                    }
                    if !emitted_for_source_sink_flow.insert(source_sink_flow_emission_key(idx, snk, call)) {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_duplicate source_rule={} sink_rule={} caller={} call={} span={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span
                        );
                        continue;
                    }
                    let evidence = cached_evidence.get_or_insert_with(|| {
                        build_call_evidence(
                            ws,
                            &trace_index,
                            &canonical_chain_index,
                            src_func_id,
                            call,
                            graph.saturated,
                        )
                    });
                    let Some(evidence) = evidence.as_ref() else {
                        lineage_misses = lineage_misses.saturating_add(1);
                        continue;
                    };
                    let taint_path = align_terminal_taint_step_to_sink(evidence.taint_path.clone(), snk);
                    let group_id = group_id_for_taint_path(&evidence.chain_names, &taint_path);
                    let flow_id = flow_id_for_taint_path(&evidence.chain_names, &taint_path);
                    if let Some(f) = make_finding(
                        src,
                        snk,
                        pack,
                        FindingBuildContext {
                            group_id: Some(group_id),
                            flow_id: Some(flow_id),
                            source_func: src_func_id,
                            sink_func: call.caller,
                            sanitizer_candidate_funcs: &evidence.sanitizer_candidate_funcs,
                            chain_names: evidence.chain_names.clone(),
                            san_by_func: &san_by_func,
                            ws,
                            tainted_call_spans: &tainted_call_spans,
                            sink_tainted_args: evidence.sink_tainted_args.clone(),
                            taint_path,
                            precision: evidence.chain_precision,
                            analysis_incomplete_reasons: unresolved_call_index
                                .reasons_for_terminal_call(call),
                        },
                    ) {
                        group_out.push(FindingWithChain {
                            finding: f,
                            chain_funcs: evidence.chain_funcs.clone(),
                        });
                    } else {
                        bonsai_diagnostics::debug_log!(
                            "security-taint",
                            "sink_match_no_finding source_rule={} sink_rule={} caller={} call={} span={:?} kind={:?} tainted_args={:?} receiver={:?}",
                            src.rule_id,
                            snk.rule_id,
                            call.caller.raw(),
                            call.name,
                            call.call_span,
                            call.kind,
                            call.tainted_args,
                            call.tainted_receiver
                        );
                    }
                }
            }
            if let Some(started) = attribution_started {
                attribution_nanos = attribution_nanos.saturating_add(started.elapsed().as_nanos());
            }
        }
        if debug_taint_phase {
            let name = global
                .decl_of(SymbolId::new(src_func_id.raw()))
                .map(|decl| decl.name.clone())
                .unwrap_or_default();
            let total_secs = group_started
                .map(|started| started.elapsed().as_secs_f64())
                .unwrap_or_default();
            bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "group func={}({}) sources={} graphs_built={} group_hits={} workspace_hits={} empty_graphs={} tainted_calls={} sink_candidates={} sink_matches={} lineage_misses={} findings={} graph={:.3}s attribution={:.3}s total={:.3}s",
                    name,
                    src_func_id.raw(),
                    indices.len(),
                    graph_builds,
                    group_graph_hits,
                    workspace_graph_hits,
                    empty_graphs,
                    tainted_calls_seen,
                    sink_candidate_checks,
                    sink_matches,
                    lineage_misses,
                    group_out.len(),
                    graph_nanos as f64 / 1_000_000_000.0,
                    attribution_nanos as f64 / 1_000_000_000.0,
                    total_secs
                );
        }
        group_out
    };
    let worker_count = security_taint_worker_count();
    let rayon_pool = if worker_count > 1 && scheduled_source_groups.len() > 1 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(worker_count)
            .build()
            .ok()
    } else {
        None
    };
    let mut run_group_indices =
        |group_indices: &[usize], idg_service: &bonsai_idg::IdgQueryService| -> Vec<Vec<FindingWithChain>> {
            if let Some(pool) = rayon_pool.as_ref().filter(|_| group_indices.len() > 1) {
                let expected_groups = group_indices.len();
                let (tx, rx) = mpsc::channel();
                let mut groups = None;
                std::thread::scope(|scope| {
                    let worker = scope.spawn(|| {
                        pool.install(|| {
                            group_indices
                                .par_iter()
                                .map(|idx| {
                                    let out = build_source_group(&scheduled_source_groups[*idx], idg_service);
                                    let _ = tx.send(());
                                    out
                                })
                                .collect::<Vec<_>>()
                        })
                    });
                    let mut completed = 0usize;
                    while completed < expected_groups {
                        match rx.recv_timeout(Duration::from_millis(250)) {
                            Ok(()) => {
                                completed += 1;
                                on_progress(AnalysisProgress::PhaseTicked);
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                if worker.is_finished() {
                                    break;
                                }
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                    // A panicking worker must surface, not silently yield zero
                    // findings: `unwrap_or_default()` would turn a crashed scan
                    // into a clean "nothing found" result. Re-raise the payload
                    // on the scope thread so the failure is visible.
                    groups = Some(match worker.join() {
                        Ok(result) => result,
                        Err(payload) => std::panic::resume_unwind(payload),
                    });
                    while completed < expected_groups {
                        on_progress(AnalysisProgress::PhaseTicked);
                        completed += 1;
                    }
                });
                return groups.unwrap_or_default();
            }
            let mut groups = Vec::with_capacity(group_indices.len());
            for idx in group_indices {
                groups.push(build_source_group(&scheduled_source_groups[*idx], idg_service));
                on_progress(AnalysisProgress::PhaseTicked);
            }
            groups
        };
    let parallel_groups: Vec<Vec<FindingWithChain>> = if use_batched_scoped_idg {
        let max_batch_funcs = 2_000usize;
        let mut batch_indices: Vec<Vec<usize>> = Vec::new();
        let mut current = Vec::new();
        let mut current_funcs: AHashSet<FuncId> = AHashSet::new();
        for (idx, group) in scheduled_source_groups.iter().enumerate() {
            let additional = group
                .corridor
                .lineage_funcs
                .iter()
                .filter(|func| !current_funcs.contains(func))
                .count();
            if !current.is_empty() && current_funcs.len().saturating_add(additional) > max_batch_funcs {
                batch_indices.push(std::mem::take(&mut current));
                current_funcs.clear();
            }
            current.push(idx);
            current_funcs.extend(group.corridor.lineage_funcs.iter().copied());
        }
        if !current.is_empty() {
            batch_indices.push(current);
        }
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "semantic graph batches planned batches={} max_funcs_per_batch={}",
            batch_indices.len(),
            max_batch_funcs
        );
        let mut groups = Vec::with_capacity(scheduled_source_groups.len());
        for (batch_number, batch) in batch_indices.iter().enumerate() {
            let mut batch_funcs: Vec<FuncId> = batch
                .iter()
                .flat_map(|idx| {
                    scheduled_source_groups[*idx]
                        .corridor
                        .lineage_funcs
                        .iter()
                        .copied()
                })
                .collect();
            batch_funcs.sort_by_key(|func| func.raw());
            batch_funcs.dedup();
            let mut batch_files: Vec<FileId> = batch_funcs
                .iter()
                .filter_map(|func| global.declaring_file(SymbolId::new(func.raw())))
                .collect();
            batch_files.sort_by_key(|file| file.raw());
            batch_files.dedup();
            bonsai_diagnostics::debug_log!(
                "security-phase",
                "building scoped semantic graph batch {}/{} groups={} funcs={} files={}",
                batch_number + 1,
                batch_indices.len(),
                batch.len(),
                batch_funcs.len(),
                batch_files.len()
            );
            let batch_idg = build_idg_service_for_rulepack_for_files(
                ws,
                pack,
                &transfer_languages,
                &batch_files,
                &batch_funcs,
                chain_call_graph.as_ref(),
            );
            groups.extend(run_group_indices(batch, batch_idg.as_ref()));
        }
        groups
    } else {
        let Some(global_idg) = idg.as_ref() else {
            return out;
        };
        let all_indices: Vec<usize> = (0..scheduled_source_groups.len()).collect();
        run_group_indices(&all_indices, global_idg.as_ref())
    };
    let parallel_out: Vec<FindingWithChain> = parallel_groups.into_iter().flatten().collect();
    out.extend(parallel_out);
    on_progress(AnalysisProgress::PhaseFinished);
    if let Some(written) = taint_cache::finish_workspace_cache(ws) {
        on_progress(AnalysisProgress::Note {
            label: "taint-cache",
            detail: format!("finish write-through entries={written}"),
        });
    } else {
        on_progress(AnalysisProgress::Note {
            label: "taint-cache",
            detail: "finish write-through failed".to_string(),
        });
    }
    out
}

fn sorted_seed_key(seeds: &TokenSet) -> Vec<String> {
    let mut sorted: Vec<String> = seeds.iter().cloned().collect();
    sorted.sort();
    sorted
}

#[derive(Clone, Default)]
struct SourceSinkCorridor {
    terminal_sinks: AHashSet<FuncId>,
    lineage_funcs: AHashSet<FuncId>,
    target_nodes: Vec<bonsai_idg::WsNodeId>,
}

impl SourceSinkCorridor {
    fn extend(&mut self, other: SourceSinkCorridor) {
        self.terminal_sinks.extend(other.terminal_sinks);
        self.lineage_funcs.extend(other.lineage_funcs);
        self.target_nodes.extend(other.target_nodes);
        self.target_nodes.sort();
        self.target_nodes.dedup();
    }
}

struct SourceCallbackTargetIndex {
    funcs_by_file: AHashMap<FileId, Vec<FuncId>>,
    funcs_by_module: AHashMap<bonsai_lang_api::ModulePath, Vec<FuncId>>,
}

impl SourceCallbackTargetIndex {
    fn build(global: &GlobalIndex) -> Self {
        let mut funcs_by_file: AHashMap<FileId, Vec<FuncId>> = AHashMap::new();
        let mut funcs_by_module: AHashMap<bonsai_lang_api::ModulePath, Vec<FuncId>> = AHashMap::new();
        for file in global.all_files() {
            for decl in global.functions_in(file) {
                let func = FuncId::new(decl.symbol.raw());
                funcs_by_file.entry(file).or_default().push(func);
                if !decl.module_path.is_empty() {
                    funcs_by_module
                        .entry(decl.module_path.clone())
                        .or_default()
                        .push(func);
                }
            }
        }
        Self {
            funcs_by_file,
            funcs_by_module,
        }
    }

    fn callback_targets_for_decl(
        &self,
        global: &GlobalIndex,
        host_decl: &bonsai_lang_api::Decl,
        callback_name: &str,
    ) -> Vec<FuncId> {
        let mut out = Vec::new();
        let mut seen = AHashSet::default();
        let host_file = global
            .declaring_file(host_decl.symbol)
            .unwrap_or(host_decl.span.file);
        if let Some(funcs) = self.funcs_by_file.get(&host_file) {
            extend_matching_callback_targets(global, funcs, callback_name, &mut out, &mut seen);
        }
        if !host_decl.module_path.is_empty() {
            if let Some(funcs) = self.funcs_by_module.get(&host_decl.module_path) {
                extend_matching_callback_targets(global, funcs, callback_name, &mut out, &mut seen);
            }
        }
        out
    }
}

fn extend_matching_callback_targets(
    global: &GlobalIndex,
    funcs: &[FuncId],
    callback_name: &str,
    out: &mut Vec<FuncId>,
    seen: &mut AHashSet<FuncId>,
) {
    for func in funcs {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        if !callback_decl_name_matches(decl, callback_name) {
            continue;
        }
        if seen.insert(*func) {
            out.push(*func);
        }
    }
}

fn callback_decl_name_matches(decl: &bonsai_lang_api::Decl, callback_name: &str) -> bool {
    callback_name_matches_tail(&decl.name, callback_name)
        || decl
            .qualified_name
            .as_deref()
            .is_some_and(|qualified| callback_name_matches_tail(qualified, callback_name))
}

fn callback_name_matches_tail(name: &str, callback_name: &str) -> bool {
    if name == callback_name {
        return true;
    }
    name.rsplit_once("::")
        .is_some_and(|(_, tail)| tail == callback_name)
        || name
            .rsplit_once('.')
            .is_some_and(|(_, tail)| tail == callback_name)
}

fn configured_source_callback_targets_by_source(
    source_work: &[(&RuleMatch, FuncId, TokenSet)],
    pack: &Rulepack,
    global: &GlobalIndex,
) -> AHashMap<FuncId, AHashSet<FuncId>> {
    if source_work.is_empty() {
        return AHashMap::new();
    }
    let index = SourceCallbackTargetIndex::build(global);
    let mut out: AHashMap<FuncId, AHashSet<FuncId>> = AHashMap::new();
    for (src, src_func_id, _) in source_work {
        let Some(src_decl) = global.decl_of(SymbolId::new(src_func_id.raw())) else {
            continue;
        };
        let Some(rule) = pack.find_rule_by_id(&src.rule_id) else {
            continue;
        };
        let Some(semantics) = rule.taint_semantics.as_ref() else {
            continue;
        };
        if semantics.source_callback_args.is_empty() {
            continue;
        }
        let Some(FlowEvent::Call { args, .. }) = find_call_event_at(&src_decl.flow_events, src.span) else {
            continue;
        };
        for shape in &semantics.source_callback_args {
            let Some(arg) = args.get(shape.callback_arg_index) else {
                continue;
            };
            let callback_text = arg
                .place
                .as_deref()
                .filter(|place| !place.trim().is_empty())
                .unwrap_or(arg.value_text.as_str());
            let callback_name = strip_source_callback_reference(callback_text);
            if callback_name.is_empty() {
                continue;
            }
            for target in index.callback_targets_for_decl(global, src_decl, callback_name) {
                if target == *src_func_id {
                    continue;
                }
                out.entry(*src_func_id).or_default().insert(target);
            }
        }
    }
    out
}

fn merge_configured_source_callback_corridors(
    coarse_corridors_by_func: &mut AHashMap<FuncId, SourceSinkCorridor>,
    source_callback_targets: &AHashMap<FuncId, AHashSet<FuncId>>,
    sink_func_set: &AHashSet<FuncId>,
    global: &GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    max_precision: Option<Precision>,
) -> AHashSet<FuncId> {
    let mut added_scope = AHashSet::default();
    let mut sorted_sources: Vec<FuncId> = source_callback_targets.keys().copied().collect();
    sorted_sources.sort_by_key(|func| func.raw());
    for source_func in sorted_sources {
        let Some(targets) = source_callback_targets.get(&source_func) else {
            continue;
        };
        let mut sorted_targets: Vec<FuncId> = targets.iter().copied().collect();
        sorted_targets.sort_by_key(|func| func.raw());
        let mut source_corridor = SourceSinkCorridor::default();
        for callback_func in sorted_targets {
            let Some(mut callback_corridor) = callgraph_source_sink_corridor(
                callback_func,
                sink_func_set,
                global,
                call_graph,
                max_precision,
            ) else {
                continue;
            };
            callback_corridor.lineage_funcs.insert(source_func);
            callback_corridor.lineage_funcs.insert(callback_func);
            source_corridor.extend(callback_corridor);
        }
        if source_corridor.terminal_sinks.is_empty() {
            continue;
        }
        extend_corridor_with_summary_dependency_support(
            &mut source_corridor,
            global,
            call_graph,
            max_precision,
        );
        added_scope.extend(source_corridor.lineage_funcs.iter().copied());
        coarse_corridors_by_func
            .entry(source_func)
            .or_default()
            .extend(source_corridor);
    }
    added_scope
}

fn strip_source_callback_reference(text: &str) -> &str {
    let mut s = text.trim();
    if let Some(open) = s.find('(') {
        if let Some(close) = s.rfind(')') {
            if open < close {
                let prefix = s[..open].trim();
                if matches!(prefix, "method" | "partial" | "fun") {
                    s = s[open + 1..close].trim();
                }
            }
        }
    }
    if let Some(rest) = s.strip_prefix("fun ") {
        s = rest.trim();
    }
    while let Some(rest) = s
        .strip_prefix('\\')
        .or_else(|| s.strip_prefix('&'))
        .or_else(|| s.strip_prefix(':'))
    {
        s = rest;
    }
    if let Some(idx) = s.find('/') {
        if s[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            s = &s[..idx];
        }
    }
    if let Some((_, tail)) = s.rsplit_once("::") {
        s = tail;
    }
    if let Some((_, tail)) = s.rsplit_once('.') {
        s = tail;
    }
    s = s.trim_matches(|c: char| c == '"' || c == '\'').trim();
    if s.is_empty() || !s.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return "";
    }
    s
}

fn extend_corridor_with_summary_dependency_support(
    corridor: &mut SourceSinkCorridor,
    global: &GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    max_precision: Option<Precision>,
) {
    let mut changed = true;
    while changed {
        changed = false;
        let lineage: Vec<FuncId> = corridor.lineage_funcs.iter().copied().collect();
        for func in lineage {
            for edge in call_graph.callees_of(func) {
                if max_precision.is_some_and(|max| edge.precision > max) {
                    continue;
                }
                if !summary_dependency_provider(global, edge.to) {
                    continue;
                }
                if corridor.lineage_funcs.insert(edge.to) {
                    changed = true;
                }
            }
        }
    }
    bonsai_workspace::extend_func_set_with_semantic_callback_dispatchers(
        &mut corridor.lineage_funcs,
        &corridor.terminal_sinks,
        global,
        call_graph,
        max_precision,
    );
}

fn source_analysis_lineage_func_scope(
    source_func: FuncId,
    global: &GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    max_precision: Option<Precision>,
    max_hops: usize,
) -> AHashSet<FuncId> {
    // Source-analysis has no sink set to cut against, so bound the graph by
    // the lineage the command is allowed to render. Summary-output providers
    // can climb back to callers, then continue forward through resolved edges.
    let mut scope = AHashSet::default();
    scope.insert(source_func);

    let mut reverse_output_funcs = AHashSet::default();
    if summary_dependency_provider(global, source_func) {
        reverse_output_funcs.insert(source_func);
    }
    let mut processed_reverse_funcs = AHashSet::default();
    let mut stack = vec![(source_func, 0usize)];

    while let Some((func, depth)) = stack.pop() {
        if depth >= max_hops {
            continue;
        }

        let mut next: Vec<FuncId> = call_graph
            .callees_of(func)
            .filter(|edge| max_precision.is_none_or(|max| edge.precision <= max))
            .map(|edge| edge.to)
            .collect();
        if reverse_output_funcs.contains(&func) && processed_reverse_funcs.insert(func) {
            next.extend(
                call_graph
                    .callers_of(func)
                    .filter(|edge| max_precision.is_none_or(|max| edge.precision <= max))
                    .map(|edge| edge.from),
            );
        }

        next.sort_by_key(|next_func| next_func.raw());
        next.dedup();
        for next_func in next.into_iter().rev() {
            if !scope.insert(next_func) {
                continue;
            }
            if summary_dependency_provider(global, next_func) {
                reverse_output_funcs.insert(next_func);
            }
            stack.push((next_func, depth.saturating_add(1)));
        }
    }

    let callback_targets = scope.clone();
    bonsai_workspace::extend_func_set_with_semantic_callback_dispatchers(
        &mut scope,
        &callback_targets,
        global,
        call_graph,
        max_precision,
    );
    scope
}

fn summary_dependency_provider(global: &GlobalIndex, func: FuncId) -> bool {
    let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
        return false;
    };
    matches!(decl.kind, DeclKind::Constructor)
        || !decl.receiver_field_writes.is_empty()
        || summary_event_outputs(&decl.flow_events)
}

fn summary_event_outputs(events: &[FlowEvent]) -> bool {
    for event in events {
        match event {
            FlowEvent::Return {
                value_text,
                value_name,
                ..
            } => {
                if value_text
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                    || value_name
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                {
                    return true;
                }
            }
            FlowEvent::Yield { value_text, .. } => {
                if value_text
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if summary_event_outputs(then_events) || summary_event_outputs(else_events) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if summary_event_outputs(body) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if summary_event_outputs(body)
                    || summary_event_outputs(catch_events)
                    || summary_event_outputs(finally_events)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

struct SinkTargetNodes {
    nodes: Vec<bonsai_idg::WsNodeId>,
    complete: bool,
    unresolved_funcs: AHashSet<FuncId>,
}

fn sink_target_nodes_for_funcs(
    idg: &bonsai_idg::IdgQueryService,
    pack: &Rulepack,
    sink_by_func: &AHashMap<FuncId, Vec<&RuleMatch>>,
    sink_funcs: &AHashSet<FuncId>,
) -> SinkTargetNodes {
    let mut sorted_sink_funcs: Vec<FuncId> = sink_funcs.iter().copied().collect();
    sorted_sink_funcs.sort_by_key(|func| func.raw());
    let mut out = Vec::new();
    let mut complete = true;
    let mut unresolved_funcs = AHashSet::new();
    let mut unresolved_rules: AHashMap<String, usize> = AHashMap::new();
    let mut unresolved_samples: Vec<String> = Vec::new();
    for sink_func in sorted_sink_funcs {
        let Some(sinks) = sink_by_func.get(&sink_func) else {
            continue;
        };
        for sink in sinks {
            let mut nodes = idg.nodes_at_span(sink_func, sink.span);
            if pack
                .find_rule_by_id(&sink.rule_id)
                .is_some_and(|rule| rule.match_spec.kind == MatchKind::Return)
            {
                if let Some(return_node) = idg.return_node_of(sink_func) {
                    nodes.push(return_node);
                }
            }
            if nodes.is_empty() {
                complete = false;
                unresolved_funcs.insert(sink_func);
                *unresolved_rules.entry(sink.rule_id.clone()).or_default() += 1;
                if unresolved_samples.len() < 12 {
                    unresolved_samples.push(format!(
                        "{} func={} {}:{}:{} text={}",
                        sink.rule_id,
                        sink_func.raw(),
                        sink.file,
                        sink.line,
                        sink.column,
                        sink.match_text
                    ));
                }
            }
            out.append(&mut nodes);
        }
    }
    out.sort();
    out.dedup();
    if !unresolved_rules.is_empty() {
        let mut top_rules: Vec<(String, usize)> = unresolved_rules.into_iter().collect();
        top_rules.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top_rules.truncate(12);
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "sink target unresolved top_rules={:?} samples={:?}",
            top_rules,
            unresolved_samples
        );
    }
    SinkTargetNodes {
        nodes: out,
        complete,
        unresolved_funcs,
    }
}

#[allow(clippy::too_many_arguments)] // Source scheduling needs rule, seed, transfer, and IDG context.
fn source_index_sink_corridor(
    index: usize,
    source_work: &[(&RuleMatch, FuncId, TokenSet)],
    pack: &Rulepack,
    config: &InterTaintConfig,
    global: &GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
    sink_target_nodes: &[bonsai_idg::WsNodeId],
    sink_target_nodes_complete: bool,
    coarse_corridor: Option<&SourceSinkCorridor>,
) -> Option<SourceSinkCorridor> {
    let (src, source_func, seeds) = source_work.get(index)?;
    let coarse_corridor = coarse_corridor?;
    if sink_target_nodes.is_empty() {
        return Some(coarse_corridor.clone());
    }
    let output_arg_names = global
        .decl_of(SymbolId::new(source_func.raw()))
        .map(|decl| output_arg_names_for_match(pack, src, decl))
        .unwrap_or_default();
    let anchor = if rule_match_kind_is_param(pack, &src.rule_id) || src.rule_id.starts_with("entry-point.") {
        None
    } else {
        Some(src.span)
    };
    let mut seed_nodes =
        effective_source_seed_nodes(*source_func, seeds, anchor, &output_arg_names, global, idg);
    if seed_nodes.is_empty() {
        return None;
    }
    apply_configured_transfer_fixpoint(
        &mut seed_nodes,
        &config.receiver_state_propagations,
        &config.call_result_passthroughs,
        &config.output_arg_flows,
        global,
        idg,
        config.max_edge_precision,
        Some(&coarse_corridor.lineage_funcs),
    );
    let cut = idg.forward_target_nodes_cut_with_max_precision(
        &seed_nodes,
        sink_target_nodes,
        config.max_edge_precision,
    );
    if cut.is_empty() {
        if bonsai_diagnostics::debug::is_enabled("security-taint") {
            let describe = |nodes: &[bonsai_idg::WsNodeId]| {
                nodes
                    .iter()
                    .map(|n| {
                        idg.resolve_point(*n)
                            .map(|p| format!("{n:?}@func{}:{:?}", p.func.raw(), p.kind))
                            .unwrap_or_else(|| format!("{n:?}:unresolved"))
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let unscoped =
                idg.forward_target_nodes_cut_with_max_precision(&seed_nodes, sink_target_nodes, None);
            bonsai_diagnostics::debug_log!(
                "security-taint",
                "empty cut rule={} seed_names={:?} anchor={:?} seeds=[{}] targets=[{}] unscoped_cut={}",
                src.rule_id,
                seeds.iter().collect::<Vec<_>>(),
                anchor,
                describe(&seed_nodes),
                describe(sink_target_nodes),
                unscoped.len()
            );
        }
        return (!sink_target_nodes_complete).then(|| coarse_corridor.clone());
    }
    let mut corridor = SourceSinkCorridor::default();
    for node in &cut {
        let Some(point) = idg.resolve_point(*node) else {
            continue;
        };
        if sink_target_nodes.binary_search(node).is_ok() {
            corridor.target_nodes.push(*node);
        }
        corridor.lineage_funcs.insert(point.func);
        if coarse_corridor.terminal_sinks.contains(&point.func) {
            corridor.terminal_sinks.insert(point.func);
        }
    }
    if corridor.terminal_sinks.is_empty() {
        return None;
    }
    corridor.lineage_funcs.insert(*source_func);
    corridor
        .lineage_funcs
        .extend(corridor.terminal_sinks.iter().copied());
    corridor.target_nodes.sort();
    corridor.target_nodes.dedup();
    Some(corridor)
}

fn callgraph_source_sink_corridor(
    source_func: FuncId,
    sink_func_set: &AHashSet<FuncId>,
    global: &GlobalIndex,
    call_graph: &bonsai_callgraph::ResolvedCallGraph,
    max_precision: Option<Precision>,
) -> Option<SourceSinkCorridor> {
    if sink_func_set.is_empty() {
        return None;
    }
    let mut seen = AHashSet::default();
    let mut forward: AHashMap<FuncId, Vec<FuncId>> = AHashMap::new();
    let mut reverse_output_funcs = AHashSet::default();
    if summary_dependency_provider(global, source_func) {
        reverse_output_funcs.insert(source_func);
    }
    let mut processed_reverse_funcs = AHashSet::default();
    let mut stack = vec![source_func];
    seen.insert(source_func);
    while let Some(func) = stack.pop() {
        let mut next: Vec<FuncId> = call_graph
            .callees_of(func)
            .filter(|edge| max_precision.is_none_or(|max| edge.precision <= max))
            .map(|edge| edge.to)
            .collect();
        if reverse_output_funcs.contains(&func) && processed_reverse_funcs.insert(func) {
            let callers: Vec<FuncId> = call_graph
                .callers_of(func)
                .filter(|edge| max_precision.is_none_or(|max| edge.precision <= max))
                .map(|edge| edge.from)
                .collect();
            for caller in callers {
                if summary_dependency_provider(global, caller) && reverse_output_funcs.insert(caller) {
                    stack.push(caller);
                }
                next.push(caller);
            }
        }
        next.sort_by_key(|callee| callee.raw());
        next.dedup();
        for next_func in &next {
            forward.entry(func).or_default().push(*next_func);
        }
        for next_func in next.into_iter().rev() {
            if seen.insert(next_func) {
                stack.push(next_func);
            }
        }
    }
    let mut terminal_sinks: AHashSet<FuncId> = seen
        .iter()
        .copied()
        .filter(|func| sink_func_set.contains(func))
        .collect();
    let mut return_sinks = AHashSet::default();
    for edge in call_graph.callers_of(source_func) {
        if max_precision.is_some_and(|max| edge.precision > max) {
            continue;
        }
        if sink_func_set.contains(&edge.from) {
            return_sinks.insert(edge.from);
        }
    }
    if terminal_sinks.is_empty() {
        if return_sinks.is_empty() {
            return None;
        }
        let mut lineage_funcs = return_sinks.clone();
        lineage_funcs.insert(source_func);
        return Some(SourceSinkCorridor {
            terminal_sinks: return_sinks,
            lineage_funcs,
            target_nodes: Vec::new(),
        });
    }
    terminal_sinks.extend(return_sinks);
    let mut reverse: AHashMap<FuncId, Vec<FuncId>> = AHashMap::new();
    for (caller, callees) in &forward {
        for callee in callees {
            if seen.contains(callee) {
                reverse.entry(*callee).or_default().push(*caller);
            }
        }
    }
    let mut lineage_funcs = terminal_sinks.clone();
    let mut frontier: Vec<FuncId> = terminal_sinks.iter().copied().collect();
    frontier.sort_by_key(|func| func.raw());
    while let Some(func) = frontier.pop() {
        let Some(callers) = reverse.get(&func) else {
            continue;
        };
        let mut sorted_callers = callers.clone();
        sorted_callers.sort_by_key(|caller| caller.raw());
        for caller in sorted_callers.into_iter().rev() {
            if lineage_funcs.insert(caller) {
                frontier.push(caller);
            }
        }
    }
    if !lineage_funcs.contains(&source_func) {
        return None;
    }
    lineage_funcs.extend(terminal_sinks.iter().copied());
    Some(SourceSinkCorridor {
        terminal_sinks,
        lineage_funcs,
        target_nodes: Vec::new(),
    })
}

fn append_taint_target_key(seed_key: &mut Vec<String>, label: &str, target_funcs: Option<&AHashSet<FuncId>>) {
    let Some(target_funcs) = target_funcs else {
        return;
    };
    let mut targets: Vec<FuncId> = target_funcs.iter().copied().collect();
    targets.sort_by_key(|func| func.raw());
    let encoded = targets
        .into_iter()
        .map(|func| func.raw().to_string())
        .collect::<Vec<_>>()
        .join(",");
    seed_key.push(format!("__{label}@{encoded}"));
}

fn append_taint_target_node_key(
    seed_key: &mut Vec<String>,
    label: &str,
    target_nodes: Option<&[bonsai_idg::WsNodeId]>,
) {
    let Some(target_nodes) = target_nodes.filter(|nodes| !nodes.is_empty()) else {
        return;
    };
    let mut nodes: Vec<bonsai_idg::WsNodeId> = target_nodes.to_vec();
    nodes.sort();
    nodes.dedup();
    let encoded = nodes
        .into_iter()
        .map(|node| node.0.to_string())
        .collect::<Vec<_>>()
        .join(",");
    seed_key.push(format!("__{label}@{encoded}"));
}

fn source_analysis_worker_count() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    let default = available.clamp(1, 4);
    std::env::var("BONSAI_SOURCE_ANALYSIS_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .map(|requested| requested.clamp(1, available))
        .unwrap_or(default)
}

fn security_taint_worker_count() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    let default = std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .map(|requested| requested.clamp(1, available))
        .unwrap_or_else(|| available.clamp(1, 4));
    std::env::var("BONSAI_TAINT_ANALYSIS_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .map(|requested| requested.clamp(1, available))
        .unwrap_or(default)
}

/// Build the cache key for an exact source-seeded graph. When an
/// anchored source match resolves to concrete IDG seed nodes, those
/// nodes are the semantic input to the closure; using them directly
/// deduplicates overlapping rule matches at the same call site
/// without merging distinct anchors that resolve to different nodes.
/// If the anchor cannot be resolved, fall back to the historical
/// name/anchor/output-arg key because the IDG seed builder will do
/// the same fallback internally.
fn effective_source_seed_key(
    source_func: FuncId,
    seeds: &TokenSet,
    anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    global: &GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<String> {
    let seed_nodes = effective_source_seed_nodes(source_func, seeds, anchor, output_arg_names, global, idg);
    if !seed_nodes.is_empty() {
        let node_ids = seed_nodes
            .iter()
            .map(|node| node.0.to_string())
            .collect::<Vec<_>>()
            .join(",");
        return vec![format!("__idg_seed_nodes@{node_ids}")];
    }
    sorted_seed_key_with_anchor(seeds, anchor, output_arg_names)
}

fn effective_source_seed_nodes(
    source_func: FuncId,
    seeds: &TokenSet,
    anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    global: &GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<bonsai_idg::WsNodeId> {
    let mut seed_nodes = Vec::new();
    // A source rule whose seed names a bare container (`args`, `env`)
    // taints every projection of that container: expand each bare name
    // with its descendant wildcard so `read_or_write_nodes_for_names`
    // also returns field-precise reads like `args.q`. Projected seeds
    // (`x.y`) stay as-is — a tainted field must never promote its
    // container or siblings.
    let seed_names = bonsai_idg::expand_bare_seed_names_with_descendants(seeds.iter());
    if anchor.is_none() {
        if seed_names.is_empty() {
            seed_nodes.extend(idg.param_nodes_of(source_func));
        } else {
            seed_nodes.extend(idg.param_nodes_for_names(source_func, &seed_names, global));
        }
        seed_nodes.extend(idg.read_or_write_nodes_for_names(source_func, &seed_names));
        seed_nodes.sort();
        seed_nodes.dedup();
        return seed_nodes;
    }
    let span = anchor.expect("checked above");
    if !output_arg_names.is_empty() {
        for arg_name in output_arg_names {
            if arg_name.is_empty() {
                continue;
            }
            seed_nodes.extend(idg.nodes_for_name_after_span(source_func, arg_name, span));
            seed_nodes.extend(output_arg_read_seed_nodes(
                source_func,
                std::slice::from_ref(arg_name),
                idg,
            ));
        }
    }
    if seed_nodes.is_empty() {
        let anchor_nodes = idg.source_seed_nodes_at_span(source_func, span);
        let anchor_has_call_return = anchor_nodes.iter().any(|node| {
            idg.resolve_point(*node)
                .is_some_and(|point| point.kind == bonsai_idg::PointKind::CallRet)
        });
        if anchor_has_call_return {
            seed_nodes = anchor_nodes;
        } else {
            seed_nodes = idg.read_or_write_nodes_for_names(source_func, &seed_names);
            // A read-kind source whose matched name is a parameter of
            // the enclosing function taints from the parameter binding.
            // The IDG routes consumers from the param / last-writer
            // node (shared `Read` places are span-less introspection
            // anchors with no forward edges of their own), so the param
            // node is what connects a bare seed like `args` to its
            // projected consumers (`args["q"]` → sink-call argument).
            seed_nodes.extend(idg.param_nodes_for_names(source_func, &seed_names, global));
            if seed_nodes.is_empty() {
                seed_nodes = anchor_nodes;
            }
        }
    }
    seed_nodes.sort();
    seed_nodes.dedup();
    seed_nodes
}

fn output_arg_read_seed_nodes(
    func: FuncId,
    output_arg_names: &[String],
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<bonsai_idg::WsNodeId> {
    let output_seed_names = bonsai_idg::expand_bare_seed_names_with_descendants(output_arg_names.iter());
    idg.read_or_write_nodes_for_names(func, &output_seed_names)
        .into_iter()
        .filter(|node| {
            idg.resolve_point(*node)
                .is_some_and(|point| point.kind == bonsai_idg::PointKind::Read)
        })
        .collect()
}

fn sorted_seed_key_with_anchor(
    seeds: &TokenSet,
    anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
) -> Vec<String> {
    let mut sorted = sorted_seed_key(seeds);
    if let Some(span) = anchor {
        sorted.push(format!(
            "__anchor@{}:{}..{}",
            span.file.raw(),
            span.start,
            span.end,
        ));
    }
    if !output_arg_names.is_empty() {
        let mut args: Vec<String> = output_arg_names.to_vec();
        args.sort();
        sorted.push(format!("__output_args@{}", args.join(",")));
    }
    sorted
}

#[allow(clippy::too_many_arguments)] // IDG source graph construction needs explicit source/sink/cache context.
fn exact_source_seed_graph(
    source_func: FuncId,
    seeds: &TokenSet,
    config: &InterTaintConfig,
    db: &bonsai_db::AnalyzerDb,
    _caches: &InterTaintCaches,
    idg: &bonsai_idg::IdgQueryService,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    target_nodes: Option<&[bonsai_idg::WsNodeId]>,
    target_funcs: Option<&AHashSet<FuncId>>,
    lineage_funcs: Option<&AHashSet<FuncId>>,
) -> EntryTaintGraph {
    // IDG-driven path. Phase 8's SSA-style CFG narrowing produces
    // correct findings for straight-line, branched, side-effecting,
    // sigil-aliased, and method-receiver flows. Callback /
    // higher-order-function flows are handled by the IDG builder's
    // callback-binding stitching pass (Phase 3 callback resolution),
    // which adds synthetic `CallArg → bound-func.Param` edges for
    // every Call whose callee name matches a function parameter,
    // walking the callgraph to find each caller's binding. The
    // rulepack's `taint_receiver_from_args` overlays are applied as
    // a closure post-pass so receiver-state inheritance survives
    // the migration without hardcoding mutator method names in the
    // IDG transfer pass.
    bonsai_taint::entry_taint_graph_from_idg_with_target_nodes_and_filters_and_max_precision(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        &config.receiver_state_propagations,
        &config.call_result_passthroughs,
        &config.output_arg_flows,
        target_nodes,
        target_funcs,
        lineage_funcs,
        config.max_edge_precision,
        db,
        idg,
    )
}

#[allow(clippy::too_many_arguments)] // IDG path graph construction needs explicit source/sink/cache context.
fn exact_source_path_graph(
    source_func: FuncId,
    seeds: &TokenSet,
    config: &InterTaintConfig,
    db: &bonsai_db::AnalyzerDb,
    _caches: &InterTaintCaches,
    ws: &Workspace,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
    target_funcs: Option<&AHashSet<FuncId>>,
    lineage_funcs: Option<&AHashSet<FuncId>>,
) -> EntryTaintGraph {
    let idg = db
        .idg_service()
        .unwrap_or_else(|| ws.build_and_seed_idg_service());
    bonsai_taint::entry_taint_call_records_from_idg_with_target_filters_and_max_precision(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        &config.receiver_state_propagations,
        &config.call_result_passthroughs,
        &config.output_arg_flows,
        target_funcs,
        lineage_funcs,
        config.max_edge_precision,
        db,
        idg.as_ref(),
    )
}

/// True when the source could syntactically reach the sink — same-fn
/// flows must have the source statement BEFORE the sink, otherwise
/// the supposed flow runs backwards in time. Cross-fn cases always
/// pass since the call graph models the temporal order separately.
fn source_can_precede_sink(
    ws: &Workspace,
    pack: &Rulepack,
    src: &RuleMatch,
    src_func: FuncId,
    snk: &RuleMatch,
    sink_func: FuncId,
) -> bool {
    if src_func != sink_func {
        return true;
    }
    if src.rule_id.starts_with("entry-point.") || rule_match_kind_is_param(pack, &src.rule_id) {
        return true;
    }
    if src.line < snk.line || (src.line == snk.line && src.column <= snk.column) {
        return true;
    }
    (src.line == snk.line && same_statement_between(ws, snk.span, src.span))
        || source_is_sink_call_argument(ws, sink_func, src.span, snk.span)
        || spans_share_enclosing_loop(ws, sink_func, src.span, snk.span)
}

fn interpolation_identifier_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for interpolation in template_interpolations(text) {
        tokens.extend(identifier_tokens_outside_strings(interpolation));
    }
    for interpolation in python_f_string_interpolations(text) {
        tokens.extend(identifier_tokens_outside_strings(interpolation));
    }
    tokens
}

fn python_f_string_interpolations(text: &str) -> Vec<&str> {
    let trimmed = text.trim_start();
    let lower = trimmed.to_ascii_lowercase();
    if !(lower.starts_with("f\"")
        || lower.starts_with("f'")
        || lower.starts_with("fr\"")
        || lower.starts_with("fr'")
        || lower.starts_with("rf\"")
        || lower.starts_with("rf'"))
    {
        return Vec::new();
    }
    braced_interpolations(trimmed)
}

fn braced_interpolations(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        if bytes.get(i + 1).copied() == Some(b'{') {
            i += 2;
            continue;
        }
        let start = i + 1;
        let mut depth = 1usize;
        let mut j = start;
        while j < bytes.len() {
            match bytes[j] {
                b'{' => depth += 1,
                b'}' => {
                    if bytes.get(j + 1).copied() == Some(b'}') && depth == 1 {
                        j += 2;
                        continue;
                    }
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        out.push(&text[start..j]);
                        i = j + 1;
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }
    }
    out
}

fn identifier_tokens_outside_strings(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            push_identifier_token(&mut tokens, &mut current);
            quote = Some(ch);
            continue;
        }
        if ch == '_' || ch.is_ascii_alphanumeric() {
            current.push(ch);
        } else {
            push_identifier_token(&mut tokens, &mut current);
        }
    }
    push_identifier_token(&mut tokens, &mut current);
    tokens
}

fn push_identifier_token(tokens: &mut Vec<String>, current: &mut String) {
    if current
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
    {
        tokens.push(std::mem::take(current));
    } else {
        current.clear();
    }
}

fn same_statement_between(ws: &Workspace, earlier: Span, later: Span) -> bool {
    if earlier.file != later.file {
        return false;
    }
    if later.start <= earlier.end {
        return true;
    }
    let Ok(snapshot) = ws.vfs().snapshot(earlier.file) else {
        return false;
    };
    let source = snapshot.text.as_ref();
    let start = earlier.end as usize;
    let end = later.start as usize;
    if start >= end || end > source.len() {
        return false;
    }
    // `start`/`end` are raw byte offsets; a multi-byte UTF-8 char straddling
    // either bound makes direct slicing panic. Fall back to "not the same
    // statement" if the range isn't on char boundaries.
    let Some(between) = source.get(start..end) else {
        return false;
    };
    !between.chars().any(|ch| matches!(ch, ';' | '\n' | '\r'))
}

fn source_is_sink_call_argument(
    ws: &Workspace,
    sink_func: FuncId,
    source_span: Span,
    sink_span: Span,
) -> bool {
    let global = ws.db().global_index();
    let Some(decl) = global.decl_of(SymbolId::new(sink_func.raw())) else {
        return false;
    };
    source_is_sink_call_argument_in_events(&decl.flow_events, source_span, sink_span)
}

fn source_is_sink_call_argument_in_events(
    events: &[bonsai_lang_api::FlowEvent],
    source_span: Span,
    sink_span: Span,
) -> bool {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } => {
                if spans_overlap(*span, sink_span)
                    && args.iter().any(|arg| span_contains(arg.span, source_span))
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if source_is_sink_call_argument_in_events(then_events, source_span, sink_span)
                    || source_is_sink_call_argument_in_events(else_events, source_span, sink_span)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if source_is_sink_call_argument_in_events(body, source_span, sink_span) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if source_is_sink_call_argument_in_events(body, source_span, sink_span)
                    || source_is_sink_call_argument_in_events(catch_events, source_span, sink_span)
                    || source_is_sink_call_argument_in_events(finally_events, source_span, sink_span)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
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
    let global = ws.db().global_index();
    let Some(decl) = global.decl_of(SymbolId::new(sink_func.raw())) else {
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
    san: &RuleMatch,
    tainted_call_spans: &AHashSet<Span>,
) -> bool {
    if !san.rule_id.contains("char_allowlist") && !san.rule_id.contains("char-allowlist") {
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
    src: &RuleMatch,
    san: &RuleMatch,
    sink_tainted_args: &[TaintedArgInfo],
) -> bool {
    let text = san.match_text.trim();
    if text.is_empty() {
        return false;
    }
    let carrier_wrapped = source_expr_base_identifier(&src.match_text).is_some_and(|carrier| {
        sink_tainted_args
            .iter()
            .any(|arg| sanitizer_call_wraps_carrier(&arg.value_text, text, carrier))
    });
    carrier_wrapped
        || sink_tainted_args
            .iter()
            .any(|arg| sanitizer_call_wraps_only_dynamic_part(&arg.value_text, text))
}

fn xxe_factory_hardening_sanitizes_sink(
    ws: &Workspace,
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
    builder_created_from_factory_before_sink(ws, san.span, snk.span, sink_receiver, factory_receiver)
}

fn receiver_text_from_match(text: &str) -> Option<&str> {
    let (receiver, _) = text.trim().rsplit_once('.')?;
    let receiver = receiver.trim();
    (!receiver.is_empty()).then_some(receiver)
}

fn builder_created_from_factory_before_sink(
    ws: &Workspace,
    san_span: Span,
    sink_span: Span,
    builder_receiver: &str,
    factory_receiver: &str,
) -> bool {
    if san_span.file != sink_span.file || san_span.end > sink_span.start {
        return false;
    }
    let Ok(snapshot) = ws.vfs().snapshot(sink_span.file) else {
        return false;
    };
    let source = snapshot.text.as_ref();
    let start = san_span.end as usize;
    let end = sink_span.start as usize;
    if start > end || end > source.len() {
        return false;
    }
    let compact = source[start..end]
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    let pattern = format!("{builder_receiver}={factory_receiver}.newDocumentBuilder(");
    compact.contains(&pattern)
}

/// True when `value_text` invokes `callee` as a CALL (anchored on the
/// `callee(` form, and `callee` not preceded by an identifier char so a
/// longer identifier such as `myEscapeHtml` never matches) and that
/// call's balanced argument list mentions `carrier` as a whole token.
fn sanitizer_call_wraps_carrier(value_text: &str, callee: &str, carrier: &str) -> bool {
    sanitizer_call_invocations(value_text, callee)
        .into_iter()
        .any(|(_, _, args)| text_mentions_token(args, carrier))
}

/// Conservative fallback for renamed flows: when the tainted sink arg is a
/// literal wrapper around a sanitizer call, the original source token may no
/// longer appear in the sink text (`input = source(); sink(escape(input))`).
/// Credit only when the sanitizer call wraps an identifier-bearing expression
/// and no value identifiers remain outside that sanitizer invocation.
fn sanitizer_call_wraps_only_dynamic_part(value_text: &str, callee: &str) -> bool {
    sanitizer_call_invocations(value_text, callee)
        .into_iter()
        .any(|(start, end, args)| {
            sanitizer_args_contain_value_identifier(args)
                && text_outside_range_has_no_value_identifiers(value_text, start, end)
        })
}

fn sanitizer_call_invocations<'a>(value_text: &'a str, callee: &str) -> Vec<(usize, usize, &'a str)> {
    if callee.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let bytes = value_text.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = value_text[search_from..].find(callee) {
        let start = search_from + rel;
        let after = start + callee.len();
        // Advance past this occurrence regardless of acceptance.
        search_from = start + 1;
        // Reject the callee being the tail of a longer identifier
        // (`myEscapeHtml`): the preceding byte must not be ident-ish.
        if start > 0 {
            let prev = bytes[start - 1];
            if prev == b'_' || prev == b'$' || prev.is_ascii_alphanumeric() {
                continue;
            }
        }
        // Require the call form `callee(`, tolerating spaces.
        let mut idx = after;
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx >= bytes.len() || bytes[idx] != b'(' {
            continue;
        }
        if let Some((end, args)) = balanced_paren_extent(value_text, idx) {
            out.push((start, end, args));
        }
    }
    out
}

fn balanced_paren_extent(text: &str, open_idx: usize) -> Option<(usize, &str)> {
    let bytes = text.as_bytes();
    if open_idx >= bytes.len() || bytes[open_idx] != b'(' {
        return None;
    }
    let mut depth = 0usize;
    let mut idx = open_idx;
    while idx < bytes.len() {
        match bytes[idx] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((idx + 1, &text[open_idx + 1..idx]));
                }
            }
            _ => {}
        }
        idx += 1;
    }
    None
}

fn sanitizer_args_contain_value_identifier(args: &str) -> bool {
    identifier_tokens_outside_strings(args)
        .iter()
        .any(|token| !non_value_expression_token(token))
}

fn text_outside_range_has_no_value_identifiers(text: &str, start: usize, end: usize) -> bool {
    let before = text.get(..start).unwrap_or_default();
    let after = text.get(end..).unwrap_or_default();
    let mut outside = String::with_capacity(before.len() + after.len() + 1);
    outside.push_str(before);
    outside.push(' ');
    outside.push_str(after);
    identifier_tokens_outside_strings(&outside)
        .iter()
        .all(|token| non_value_expression_token(token))
}

fn non_value_expression_token(token: &str) -> bool {
    matches!(
        token,
        "await"
            | "false"
            | "nil"
            | "None"
            | "null"
            | "return"
            | "self"
            | "this"
            | "true"
            | "undefined"
            | "new"
            | "String"
            | "Integer"
            | "Long"
            | "Boolean"
            | "Byte"
            | "Bytes"
            | "Object"
    )
}

/// True when `token` appears in `text` as a whole identifier (not as a
/// substring of a longer identifier). Empty token never matches.
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
            let b = bytes[start - 1];
            !(b == b'_' || b == b'$' || b.is_ascii_alphanumeric())
        };
        let after_ok = end >= bytes.len() || {
            let b = bytes[end];
            !(b == b'_' || b == b'$' || b.is_ascii_alphanumeric())
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
    sink_tainted_args: &[TaintedArgInfo],
    dataflow_connected: bool,
    post_sink_path_construction_containment: bool,
) -> bool {
    if sanitizer_func == source_func && !match_precedes_or_same(src, san) && !dataflow_connected {
        return false;
    }
    if sanitizer_func == sink_func
        && !match_precedes_or_same(san, snk)
        && !sanitizer_is_nested_in_tainted_sink_arg(src, san, sink_tainted_args)
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
    let global = ws.db().global_index();
    let Some(decl) = global.decl_of(SymbolId::new(sanitizer_func.raw())) else {
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
        .flat_map(|arg| clean_overwrite_target_keys(&arg.value_text))
        .collect();
    if target_keys.is_empty() && sink_rule.match_spec.kind == MatchKind::Return {
        target_keys.extend(clean_overwrite_target_keys(&snk.match_text));
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

fn sanitizer_guard_feeds_sink_arg(
    ws: &Workspace,
    sanitizer_func: FuncId,
    sanitizer_rule: Option<&Rule>,
    san: &RuleMatch,
    snk: &RuleMatch,
    sink_tainted_args: &[TaintedArgInfo],
) -> bool {
    let Some(tag) = sanitizer_rule.and_then(|rule| rule.tag.as_deref()) else {
        return false;
    };
    if !matches!(tag, "same-origin-path" | "ssrf-sanitize" | "allowlist-validate")
        || san.span.file != snk.span.file
        || !match_precedes_or_same(san, snk)
    {
        return false;
    }
    let target_keys: AHashSet<String> = sink_tainted_args
        .iter()
        .flat_map(|arg| clean_overwrite_target_keys(&arg.value_text))
        .filter(|target| !looks_like_clean_constant(target))
        .collect();
    if target_keys.is_empty() {
        return false;
    }
    let global = ws.db().global_index();
    let Some(decl) = global.decl_of(SymbolId::new(sanitizer_func.raw())) else {
        return false;
    };
    let mut guarded = sanitizer_guard_variables_in_events(&decl.flow_events, san, tag);
    if guarded.is_empty() {
        guarded.extend(sanitizer_guard_variables_from_source_line(ws, san, tag));
    }
    guarded.retain(|var| !looks_like_clean_constant(var));
    if guarded.is_empty() {
        return false;
    }
    let guarded_set: AHashSet<String> = guarded.into_iter().collect();
    if target_keys.iter().any(|target| guarded_set.contains(target)) {
        return true;
    }
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
    )
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

fn sanitizer_guard_variables_from_source_line(ws: &Workspace, san: &RuleMatch, tag: &str) -> Vec<String> {
    let Ok(snapshot) = ws.vfs().snapshot(san.span.file) else {
        return Vec::new();
    };
    let Some(line) = source_line_text(&snapshot.text, san.line) else {
        return Vec::new();
    };
    match tag {
        "same-origin-path" => receiver_before_call_token(line, &san.match_text)
            .into_iter()
            .collect(),
        "ssrf-sanitize" | "allowlist-validate" => call_argument_identifiers_after(line, &san.match_text),
        _ => Vec::new(),
    }
}

fn receiver_before_call_token(line: &str, match_text: &str) -> Option<String> {
    let token = match_text.trim();
    let dot = token.rfind('.')?;
    clean_overwrite_target_key(&token[..dot]).or_else(|| {
        line.find(token)
            .and_then(|idx| line[..idx].rsplit('.').next())
            .and_then(clean_overwrite_target_key)
    })
}

fn call_argument_identifiers_after(line: &str, match_text: &str) -> Vec<String> {
    let token = match_text.trim();
    let Some(start) = line.find(token) else {
        return Vec::new();
    };
    let after = &line[start + token.len()..];
    let Some(open_rel) = after.find('(') else {
        return Vec::new();
    };
    let open = start + token.len() + open_rel;
    let Some((_, args)) = balanced_paren_extent(line, open) else {
        return Vec::new();
    };
    let mut vars: Vec<String> = identifier_tokens_outside_strings(args)
        .into_iter()
        .filter_map(|token| clean_overwrite_target_key(&token))
        .filter(|token| !non_value_expression_token(token))
        .collect();
    vars.sort();
    vars.dedup();
    vars
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
) -> bool {
    for event in events {
        match event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                args,
                ..
            } if span.file == sink_span.file
                && guard_span.end <= span.start
                && span.start <= sink_span.start =>
            {
                let Some(receiver) = receiver.as_deref().and_then(clean_overwrite_target_key) else {
                    continue;
                };
                if !receiver_targets.contains(&receiver) || !name.ends_with("setLocation") {
                    continue;
                }
                if args.iter().any(|arg| {
                    clean_overwrite_target_keys(&arg.value_text)
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
                ) || guarded_variable_flows_into_receiver_before_sink(
                    else_events,
                    guard_span,
                    sink_span,
                    guarded,
                    receiver_targets,
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
                ) || guarded_variable_flows_into_receiver_before_sink(
                    catch_events,
                    guard_span,
                    sink_span,
                    guarded,
                    receiver_targets,
                ) || guarded_variable_flows_into_receiver_before_sink(
                    finally_events,
                    guard_span,
                    sink_span,
                    guarded,
                    receiver_targets,
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
    matches!(
        sink_rule.id.as_str(),
        "go.path.filepath_join" | "go.path.path_join"
    )
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

/// Prototype-pollution merge/write rules are intentionally broad once
/// tainted keys reach dynamic property writes. A nearby denylist guard
/// for the exact index variable is a semantic barrier: the dangerous
/// prototype carrier keys cannot reach this write.
fn prototype_pollution_sink_is_guarded(ws: &Workspace, sink_rule: &Rule, sink: &RuleMatch) -> bool {
    if sink_rule.tag.as_deref() != Some("prototype-pollution")
        || !matches!(sink.language.as_str(), "javascript" | "typescript")
    {
        return false;
    }

    let Ok(snapshot) = ws.vfs().snapshot(sink.span.file) else {
        return false;
    };
    let source = snapshot.text.as_ref();
    let sink_start = sink.span.start as usize;
    let sink_end = sink.span.end as usize;
    if sink_start > source.len() {
        return false;
    }
    let sink_text = source
        .get(sink_start..sink_end.min(source.len()))
        .unwrap_or(sink.match_text.as_str());
    let mut key_vars = prototype_key_index_variables(sink_text);
    if key_vars.is_empty() {
        if let Some(line_text) = source_line_text(source, sink.line) {
            key_vars.extend(prototype_key_index_variables(line_text));
            key_vars.sort();
            key_vars.dedup();
        }
    }
    if key_vars.is_empty() && sink.match_text.contains(".key") {
        key_vars.push("key".to_string());
    }
    if key_vars.is_empty() {
        return false;
    }

    let scope_start = ws
        .enclosing_index()
        .enclosing_for(ws.db(), sink.span.file, sink.span.start)
        .map(|entry| entry.start as usize)
        .unwrap_or_else(|| sink_start.saturating_sub(1200));
    let guard_start = scope_start.max(sink_start.saturating_sub(1200));
    let Some(prefix) = source.get(guard_start..sink_start) else {
        return false;
    };
    let compact = compact_guard_text(prefix);
    if compact.contains("Object.freeze(Object.prototype)") {
        return true;
    }

    if key_vars
        .iter()
        .any(|key| prototype_key_denylist_guard_present(&compact, key))
    {
        return true;
    }

    let wide_guard_start = sink_start.saturating_sub(1200);
    if wide_guard_start < guard_start {
        if let Some(prefix) = source.get(wide_guard_start..sink_start) {
            let compact = compact_guard_text(prefix);
            return compact.contains("Object.freeze(Object.prototype)")
                || key_vars
                    .iter()
                    .any(|key| prototype_key_denylist_guard_present(&compact, key));
        }
    }
    false
}

fn prototype_key_index_variables(text: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('[') {
        rest = &rest[open + 1..];
        let Some(close) = rest.find(']') else {
            break;
        };
        let candidate = rest[..close].trim();
        if is_js_identifier(candidate) && !vars.iter().any(|existing| existing == candidate) {
            vars.push(candidate.to_string());
        }
        rest = &rest[close + 1..];
    }
    vars
}

fn source_line_text(source: &str, one_based_line: u32) -> Option<&str> {
    if one_based_line == 0 {
        return None;
    }
    source.lines().nth(usize::try_from(one_based_line - 1).ok()?)
}

fn is_js_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first == '$' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())
}

fn compact_guard_text(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn prototype_key_denylist_guard_present(compact: &str, key: &str) -> bool {
    let has_abrupt_exit =
        compact.contains("continue;") || compact.contains("return;") || compact.contains("throw");
    if !has_abrupt_exit {
        return false;
    }

    const DANGEROUS_KEYS: &[&str] = &["__proto__", "constructor", "prototype"];
    let compares_all = DANGEROUS_KEYS
        .iter()
        .all(|dangerous| prototype_key_compare_present(compact, key, dangerous));
    if compares_all {
        return true;
    }

    let mentions_all_keys = DANGEROUS_KEYS.iter().all(|dangerous| compact.contains(dangerous));
    mentions_all_keys
        && (compact.contains(&format!(".includes({key})")) || compact.contains(&format!(".has({key})")))
}

fn prototype_key_compare_present(compact: &str, key: &str, dangerous: &str) -> bool {
    [
        format!(r#"{key}==="{dangerous}""#),
        format!(r#"{key}=="{dangerous}""#),
        format!(r#""{dangerous}"==={key}"#),
        format!(r#""{dangerous}"=={key}"#),
        format!("{key}==='{dangerous}'"),
        format!("{key}=='{dangerous}'"),
        format!("'{dangerous}'==={key}"),
        format!("'{dangerous}'=={key}"),
    ]
    .iter()
    .any(|needle| compact.contains(needle))
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
    if src.rule_id.starts_with("entry-point.") || rule_match_kind_is_param(pack, &src.rule_id) {
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
    for event in events {
        match event {
            FlowEvent::Call { span, .. }
                if *span == target || span_contains(*span, target) || spans_overlap(*span, target) =>
            {
                return Some(event);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(v) = find_call_event_at(then_events, target) {
                    return Some(v);
                }
                if let Some(v) = find_call_event_at(else_events, target) {
                    return Some(v);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(v) = find_call_event_at(body, target) {
                    return Some(v);
                }
                if let Some(v) = find_call_event_at(catch_events, target) {
                    return Some(v);
                }
                if let Some(v) = find_call_event_at(finally_events, target) {
                    return Some(v);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(v) = find_call_event_at(body, target) {
                    return Some(v);
                }
            }
            _ => {}
        }
    }
    None
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

fn source_seed_set(
    pack: &Rulepack,
    src: &RuleMatch,
    decl: &bonsai_lang_api::Decl,
    value_flow: Option<&ValueFlowGraph>,
) -> TokenSet {
    let mut out = TokenSet::default();
    let is_inferred = src.rule_id.starts_with("entry-point.");
    let rule = pack.find_rule_by_id(&src.rule_id);
    let is_param_rule = value_flow_match::is_param_rule(src, pack);
    let source_output_args = rule
        .and_then(|rule| rule.taint_semantics.as_ref())
        .map(|semantics| semantics.source_output_args.as_slice())
        .unwrap_or(&[]);
    let source_callback_args = rule
        .and_then(|rule| rule.taint_semantics.as_ref())
        .map(|semantics| semantics.source_callback_args.as_slice())
        .unwrap_or(&[]);
    if let Some(graph) = value_flow {
        seed_source_nodes_from_value_flow(src, graph, &mut out);
    }
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
        include_diagnostic_field_flows: false,
        include_receiver_method_propagation: false,
        include_field_argument_forwarding: true,
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
    let options = idg_transfer_options_from_rulepack_shapes(&overwrites, &source_outputs, &source_callbacks);
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
    let mut options =
        idg_transfer_options_from_rulepack_shapes(&overwrites, &source_outputs, &source_callbacks);
    let large_java_scope = languages.contains("java") && included_funcs.len() > 1_000;
    options.include_receiver_method_propagation = !large_java_scope;
    if large_java_scope {
        options.include_field_argument_forwarding = false;
    }
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "semantic graph transfer options large_java_scope={} languages={} funcs={} receiver_method_propagation={} field_argument_forwarding={}",
        large_java_scope,
        languages.len(),
        included_funcs.len(),
        options.include_receiver_method_propagation,
        options.include_field_argument_forwarding
    );
    ws.build_and_seed_idg_service_with_transfer_options_for_files_and_call_graph(
        &options,
        included_files,
        included_funcs,
        call_graph,
    )
}

fn build_idg_service_for_rulepack_for_files(
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
    let mut options =
        idg_transfer_options_from_rulepack_shapes(&overwrites, &source_outputs, &source_callbacks);
    let large_java_scope = languages.contains("java") && included_funcs.len() > 1_000;
    options.include_receiver_method_propagation = !large_java_scope;
    if large_java_scope {
        options.include_field_argument_forwarding = false;
    }
    bonsai_diagnostics::debug_log!(
        "security-phase",
        "semantic graph transfer options large_java_scope={} languages={} funcs={} receiver_method_propagation={} field_argument_forwarding={}",
        large_java_scope,
        languages.len(),
        included_funcs.len(),
        options.include_receiver_method_propagation,
        options.include_field_argument_forwarding
    );
    ws.build_idg_service_with_transfer_options_for_files_and_call_graph(
        &options,
        included_files,
        included_funcs,
        call_graph,
    )
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
        .filter(|rule| rule.enabled && rule.kind == RuleKind::Sanitizer)
        .filter_map(|rule| {
            let semantics = rule.taint_semantics.as_ref()?;
            if semantics.call_result_passthrough_args.is_empty()
                && !semantics.call_result_passthrough_receiver
            {
                return None;
            }
            let callee = rule
                .match_spec
                .callee
                .as_ref()
                .and_then(semantic_transfer_callee)?;
            let mut input_arg_indices = semantics.call_result_passthrough_args.clone();
            input_arg_indices.sort_unstable();
            input_arg_indices.dedup();
            Some(CallResultPassthrough {
                callee,
                input_arg_indices,
                input_receiver: semantics.call_result_passthrough_receiver,
            })
        })
        .collect();
    sort_call_result_passthroughs(&mut out);
    out
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
                && rule.kind == RuleKind::Sink
                && rule_has_taint_predicate(rule)
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
        (&a.callee, &a.input_arg_indices, a.input_receiver).cmp(&(
            &b.callee,
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

        let seeds = source_seed_set(&Rulepack::default(), &source, &decl, None);

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

        let nodes = effective_source_seed_nodes(func, &seeds, Some(anchor), &[], &global, &service);
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
pub(crate) mod value_flow_match;
