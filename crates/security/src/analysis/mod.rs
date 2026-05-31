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
    infer_entry_point_sources, match_rules_against_facts_for_sink_inventory,
    match_rules_against_facts_for_taint_with_progress, match_rules_against_facts_with_progress,
    rule_match_passes_constraints_with_taint_view, InterTaintView, RuleMatch,
};
use crate::rule::{ConstraintKind, MatchKind, Rule, RuleKind, RuleTarget, Severity};
use crate::sanitizer_credit::{sanitizer_credits_sink_tag, sanitizer_tag_is_recognized_non_crediting};
use ahash::{AHashMap, AHashSet};
use anyhow::Result;
use bonsai_common::{FuncId, Precision, Span, SymbolId};
use bonsai_lang_api::LanguageRegistry;
use bonsai_taint::{
    CallResultPassthrough, CleanOutputOverwrite, EntryTaintGraph, InterTaintCaches, InterTaintConfig,
    OutputArgFlow, ReceiverStatePropagation, SourceOutputArgs, TaintedCall, TaintedCallEdge, TokenSet,
    ValueFlowGraph,
};
use bonsai_workspace::Workspace;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

type RankedCallPath = std::cmp::Reverse<(i64, u32, u32, Vec<FuncId>)>;
type InventoryMatchIdentity = (String, String, u32, u32, String, String, Option<String>);

/// Phase-aware progress event emitted by `run_taint_analysis_with_phase_progress`
/// and `run_source_analysis_with_phase_progress`. Long-running phases
/// announce themselves with a known total, then tick once per item;
/// callers can render a progress bar per phase without having to
/// hard-code phase totals on the UI side.
#[derive(Clone, Copy, Debug)]
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
}

#[derive(Clone, Debug)]
pub struct TaintAnalysisOptions {
    pub source: Option<String>,
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
    /// Deprecated compatibility switch. Sanitizer rules are now evidence
    /// attached to propagated paths, not propagation blockers, so sanitized
    /// paths are always present when source-to-sink reachability exists.
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
}

impl Default for TaintAnalysisOptions {
    fn default() -> Self {
        Self {
            source: None,
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
            max_precision: Some(Precision::Narrowed),
            exclude_tests: false,
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
            _ => Precision::Narrowed,
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
/// so the canonical web-family audit matrix should render as not
/// applicable rather than as a wall of false coverage gaps.
pub const ECOSYSTEM_SPECIFIC_SINK_AUDIT_LANGS: &[&str] = &["solidity"];

/// Specific `(language, family)` cells where the empty state is a
/// deliberate design choice, not missing coverage.
pub const FAMILY_NOT_APPLICABLE: &[(&str, &str)] = &[("c", "deserialization")];

#[derive(Clone, Debug, Serialize)]
pub struct FindingWithChain {
    #[serde(flatten)]
    pub finding: Finding,
    #[serde(skip)]
    pub chain_funcs: Vec<FuncId>,
}

/// A rendered finding may contain multiple source/sink sites when they
/// collapse onto the same resolved semantic flow.
#[derive(Clone, Debug, Serialize)]
pub struct CombinedFindingWithChain {
    #[serde(flatten)]
    pub finding: Finding,
    #[serde(skip)]
    pub chain_funcs: Vec<FuncId>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub additional_sources: Vec<FindingMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub additional_sinks: Vec<FindingMatch>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub member_finding_ids: Vec<String>,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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
    filter_rules_to_workspace_languages(ws, &mut sources);
    filter_rules_to_workspace_languages(ws, &mut sinks);
    filter_rules_to_workspace_languages(ws, &mut sanitizers);
    let selected_sink_rule_count = sinks.len();

    let total_files = ws.db().global_index().all_files().count() as u64;
    let mut source_hits = gather_matches_phased(
        ws,
        &sources,
        "matching source rules",
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
        source_hits.extend(
            infer_entry_point_sources(ws)
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
    filter_by_path(&mut source_hits, &options.files, &options.exclude_files);

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

    on_progress(AnalysisProgress::PhaseStarted {
        label: "matching sink rules",
        total: total_files,
    });
    let mut sink_hits = match_rules_against_facts_for_taint_with_progress(ws, &sinks, || {
        on_progress(AnalysisProgress::PhaseTicked);
    });
    on_progress(AnalysisProgress::PhaseFinished);
    let mut sanitizer_hits = gather_matches_phased(
        ws,
        &sanitizers,
        "matching sanitizer rules",
        total_files,
        &mut on_progress,
    );
    filter_by_path(&mut sink_hits, &options.files, &options.exclude_files);
    filter_by_path(&mut sanitizer_hits, &options.files, &options.exclude_files);

    let mut pattern_sink_hits = if pattern_sinks.is_empty() {
        Vec::new()
    } else {
        gather_matches_phased(
            ws,
            &pattern_sinks,
            "matching pattern sink rules",
            total_files,
            &mut on_progress,
        )
    };
    filter_by_path(&mut pattern_sink_hits, &options.files, &options.exclude_files);

    // Pre-filter test-path matches when --exclude-tests is set so the
    // expensive per-source-graph + chain-build phase never even sees
    // them. Without this prune, lodash spends ~60s of interprocedural
    // work on a 27 k-line `test/test.js` IIFE before the post-hoc
    // `from_test` filter throws the findings away. Dropping the
    // matches here keeps the post-hoc filter as a safety net for
    // edge cases (cross-file flows where one side is a test path).
    if options.exclude_tests {
        source_hits.retain(|m| !crate::finding::path_is_test_file(&m.file));
        sink_hits.retain(|m| !crate::finding::path_is_test_file(&m.file));
        pattern_sink_hits.retain(|m| !crate::finding::path_is_test_file(&m.file));
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

    // Exact security analysis relies on value-flow to choose source
    // seeds before it builds source-seeded taint graphs. Query-only
    // workspace opens do not eager-build the IDG, so force it here
    // once for the requested analysis scope; otherwise value-flow
    // falls back to the legacy per-source interprocedural engine and
    // broad scans recompute the same workspace facts hundreds of times.
    if !source_hits.is_empty() && !sink_hits.is_empty() {
        seed_idg_service_for_rulepack(ws, pack);
    }

    let mut findings_raw = build_findings_chain_aware(
        ws,
        &source_hits,
        &sink_hits,
        &sanitizer_hits,
        pack,
        options.interprocedural_budget,
        options.intra_worklist_cap,
        options.max_precision,
        &mut on_progress,
    );
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
            !finding_has_excluded_path(&combined.finding, &options.exclude_files, options.exclude_tests)
        });
    }
    if options.exclude_tests {
        // Test-path post-filter — catches cross-file flows where one
        // side wasn't pruned earlier (e.g. prod source → test sink).
        findings.retain(|combined| !combined.finding.from_test);
    }
    drop_dominated_wrapper_findings(&mut findings);
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
    // Sort highest-severity-first, then by finding id so two runs
    // produce identical output ordering.
    findings.sort_by(|a, b| {
        b.finding
            .severity
            .cmp(&a.finding.severity)
            .then_with(|| a.finding.finding_id.cmp(&b.finding.finding_id))
    });

    // Embed per-hop source bodies so JSON/SARIF carry the same code the text
    // view renders. Done last, on surviving findings only, so filtered-out
    // findings never pay the VFS read.
    for combined in &mut findings {
        combined.finding.hops = crate::flow_evidence::build_flow_bodies(
            ws,
            &combined.chain_funcs,
            &combined.finding.source,
            &combined.finding.taint_path,
            crate::flow_evidence::FlowRole::Sink,
        );
    }

    Ok(TaintAnalysisReport {
        findings,
        source_rule_count: sources.len(),
        sink_rule_count: selected_sink_rule_count,
        sanitizer_rule_count: sanitizers.len(),
    })
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

    let total_files = ws.db().global_index().all_files().count() as u64;
    let mut source_hits = gather_matches_phased(
        ws,
        &sources,
        "matching source rules",
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
        source_hits.extend(
            infer_entry_point_sources(ws)
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
    filter_by_path(&mut source_hits, &options.files, &options.exclude_files);
    if options.exclude_tests {
        source_hits.retain(|m| !crate::finding::path_is_test_file(&m.file));
    }
    sort_matches(&mut source_hits);

    // Source-analysis is exact and source-seeded, but its source
    // selection pass asks value-flow for per-function seed shape.
    // Seed/load the IDG once before that fan-out so value-flow uses
    // the workspace graph instead of repeatedly invoking the legacy
    // interprocedural engine for every source match.
    if !source_hits.is_empty() {
        seed_idg_service_for_rulepack(ws, pack);
    }

    let global = ws.db().global_index();
    let source_graph_config = InterTaintConfig {
        sanitizers: TokenSet::default(),
        budget: InterTaintConfig::default().budget,
        intra_worklist_cap: None,
        source_bearing_functions: AHashSet::default(),
        clean_output_overwrites: clean_output_overwrites_from_rulepack(pack),
        source_output_args: source_output_args_from_rulepack(pack),
        call_result_passthroughs: call_result_passthroughs_from_rulepack(pack),
        output_arg_flows: output_arg_flows_from_rulepack(pack),
        receiver_state_propagations: receiver_state_propagations_from_rulepack(pack),
        max_edge_precision: Some(Precision::Narrowed),
        ..Default::default()
    };
    let source_graph_caches = ws.inter_taint_caches();
    on_progress(AnalysisProgress::PhaseStarted {
        label: "enumerating source paths",
        total: source_hits.len() as u64,
    });
    // Exact source-seeded graphs are cached through the workspace
    // `TaintGraphIndex`, which is bounded in memory and keyed by a
    // rule/config fingerprint. Disk persistence is opt-in because
    // broad exact scans can produce multi-GB graph payloads; cache
    // eviction only drops a performance artifact, never an analysis
    // result.
    let workspace_taint_index = ws.taint_index();
    let source_graph_fingerprint =
        taint_graph_config_fingerprint(pack, "source-analysis", source_graph_config.max_edge_precision);
    prepare_workspace_taint_graph_cache(ws, source_graph_fingerprint);
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

    let mut source_jobs: Vec<(usize, SourceGraphJob)> = Vec::new();
    for (start, hits) in hits_by_func_sorted {
        let Some(decl) = global.decl_of(SymbolId::new(start.raw())) else {
            continue;
        };
        // The transient value-flow graph is only needed to derive
        // source seed shape. Build it once per source-bearing
        // function, derive every matching source seed in that
        // function, then drop the graph before moving on. This keeps
        // broad source-analysis scans exact without recomputing the
        // same function-local value-flow graph for every source hit.
        let value_flow = ws
            .value_flow()
            .graph_for_transient_with_caches(start, ws.db(), source_graph_caches);
        for hit in hits {
            let seeds = source_seed_set(pack, hit.hit, decl, Some(value_flow.as_ref()));
            let output_arg_names = output_arg_names_for_match(pack, hit.hit, decl);
            let anchor = if rule_match_kind_is_param(pack, &hit.hit.rule_id) {
                None
            } else {
                Some(hit.hit.span)
            };
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
                jobs: vec![job],
            });
        }
    }
    source_groups.sort_by_key(|group| group.first_index);
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
                Ok(pool) => pool.install(|| {
                    source_groups
                        .par_iter()
                        .enumerate()
                        .map(|(idx, group)| (idx, build_group_candidates(group)))
                        .collect()
                }),
                Err(_) => source_groups
                    .iter()
                    .enumerate()
                    .map(|(idx, group)| (idx, build_group_candidates(group)))
                    .collect(),
            }
        } else {
            source_groups
                .iter()
                .enumerate()
                .map(|(idx, group)| (idx, build_group_candidates(group)))
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
    for _ in 0..source_hits.len() {
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
    finish_workspace_taint_graph_cache(ws);
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
    for file in ws.db().global_index().all_files() {
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
    let mut matches = match_rules_against_facts_with_progress(ws, &selected, || {});
    filter_by_path(&mut matches, &options.files, &options.exclude_files);
    sort_matches(&mut matches);
    dedup_inventory_matches(&mut matches);
    Ok(matches)
}

pub fn sink_inventory(
    ws: &Workspace,
    pack: &Rulepack,
    options: SecurityInventoryOptions,
) -> Result<Vec<RuleMatch>> {
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
    let mut matches = match_rules_against_facts_for_sink_inventory(ws, &selected);
    filter_by_path(&mut matches, &options.files, &options.exclude_files);
    sort_matches(&mut matches);
    dedup_inventory_matches(&mut matches);
    Ok(matches)
}

pub fn sanitizer_inventory(
    ws: &Workspace,
    pack: &Rulepack,
    options: SecurityInventoryOptions,
) -> Result<Vec<RuleMatch>> {
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
    let mut matches = match_rules_against_facts_with_progress(ws, &selected, || {});
    filter_by_path(&mut matches, &options.files, &options.exclude_files);
    sort_matches(&mut matches);
    dedup_inventory_matches(&mut matches);
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
    if !options.files.is_empty() {
        inv.rows.retain(|row| {
            row.evidence_files
                .iter()
                .any(|evidence| options.files.iter().any(|file| evidence.contains(file)))
        });
    }
    if !options.exclude_files.is_empty() {
        inv.rows.retain(|row| {
            !row.evidence_files
                .iter()
                .any(|evidence| options.exclude_files.iter().any(|file| evidence.contains(file)))
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
                let entry = sink_counts
                    .entry((rule.language.clone(), rule_family(&rule.id).to_string()))
                    .or_insert((0, 0));
                if rule.enabled {
                    entry.0 += 1;
                } else {
                    entry.1 += 1;
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
            PackAuditLanguage {
                language,
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

pub fn validate_pack(
    pack: &Rulepack,
    options: &PackInventoryOptions,
    registry: Arc<LanguageRegistry>,
) -> PackValidationReport {
    struct ValidationExample<'a> {
        owner: &'a Rule,
        example: &'a crate::rule::RuleMatchExample,
        ws: Workspace,
    }

    let rules = select_pack_rules(pack, options);
    let mut issues = Vec::new();
    let mut example_count = 0usize;
    let mut enabled_example_count = 0usize;
    let enabled_rule_count = rules.iter().filter(|rule| rule.enabled).count();
    let disabled_rule_count = rules.len().saturating_sub(enabled_rule_count);
    let disabled_waiting_reenable_count = rules
        .iter()
        .filter(|rule| {
            !rule.enabled
                && rule
                    .disabled_reason
                    .as_ref()
                    .is_some_and(|reason| reason.code.waits_on_reenable_work())
        })
        .count();
    let mut disabled_reason_counts: BTreeMap<String, usize> = BTreeMap::new();
    for rule in rules.iter().filter(|rule| !rule.enabled) {
        if let Some(reason) = &rule.disabled_reason {
            *disabled_reason_counts
                .entry(reason.code.as_str().to_string())
                .or_default() += 1;
        }
    }
    let id_seen: BTreeSet<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();

    // R3 invariant: a disabled rule with `disabled_reason.subsumed_by`
    // must point at a rule that is itself ENABLED. Catching broken
    // chains at validate-time prevents the "X claims subsumed by Y;
    // Y is also disabled" coverage gap that the audit caught
    // manually. Per
    // docs/pattern-guide.mdx::"Disabled Rule Reasons" — the
    // `subsumed_by` field is the rule's promise to consumers that
    // the named canonical covers the same surface.
    let enabled_ids: BTreeSet<&str> = rules
        .iter()
        .filter(|r| r.enabled)
        .map(|r| r.id.as_str())
        .collect();
    for rule in rules.iter().filter(|r| !r.enabled) {
        let Some(reason) = &rule.disabled_reason else {
            continue;
        };
        let Some(target) = reason.subsumed_by.as_deref() else {
            continue;
        };
        if !id_seen.contains(target) {
            push_validation_issue(
                &mut issues,
                "error",
                "subsumed-by-target-missing",
                Some(rule),
                &format!(
                    "`disabled_reason.subsumed_by: {target}` names a rule that doesn't \
                     exist in the loaded pack. Either fix the target id or replace \
                     `subsumed_by` with `over-broad` / `requires-constraint`."
                ),
            );
        } else if !enabled_ids.contains(target) {
            push_validation_issue(
                &mut issues,
                "error",
                "subsumed-by-target-disabled",
                Some(rule),
                &format!(
                    "`disabled_reason.subsumed_by: {target}` names a rule that is also \
                     disabled — both halves of the chain are off, leaving the surface \
                     uncovered. Either redirect `subsumed_by` to the working canonical \
                     or change `disabled_reason.code` to `over-broad` and clear the \
                     `subsumed_by` field."
                ),
            );
        }
    }

    let mut enabled_examples = Vec::new();

    for rule in &rules {
        validate_rule_metadata(rule, &mut issues);
        if rule.enabled && rule.match_examples.is_empty() {
            push_validation_issue(
                &mut issues,
                "error",
                "missing-match-example",
                Some(rule),
                "enabled rules must include at least one match_examples entry",
            );
        }
        let signals: Vec<&str> = rule
            .packages
            .iter()
            .chain(rule.imports.iter())
            .chain(rule.modules.iter())
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .collect();
        let mut example_imports: BTreeSet<String> = BTreeSet::new();
        let mut arg_tainted_index_seen: BTreeMap<u32, bool> = rule
            .constraints
            .iter()
            .filter_map(|constraint| match constraint {
                ConstraintKind::ArgTainted { arg_tainted } => arg_tainted.index,
                _ => None,
            })
            .map(|index| (index, false))
            .collect();
        // Disabled rules document examples as known canonical shapes
        // that the current adapter+matcher pipeline may not fire on
        // (`pending-adapter-fact`, `over-broad`, etc. — see the
        // `disabled_reason.code` enum). Skip the example body for
        // those: `match-example-owner-miss`,
        // `match-example-missing-import`, expected-match-text, and
        // arg-tainted-index checks all assume the matcher pipeline
        // can fire, which is by definition not true for disabled
        // rules. Static metadata checks still run for disabled rules
        // so we catch typos / structural drift in disabled YAML too.
        if !rule.enabled {
            // Bump informational counter so disabled rules still
            // report `example_count` accurately, but skip the rest.
            example_count += rule.match_examples.len();
            validate_constraint_coverage(rule, &mut issues);
            continue;
        }
        for example in &rule.match_examples {
            example_count += 1;
            enabled_example_count += 1;
            let ws = example_workspace(
                &rule.language,
                example.path.as_deref(),
                &example.code,
                registry.clone(),
            );
            // Tree-sitter import-index check (no regex). Rules that
            // use receiver-agnostic regexes plus package/module
            // signals need at least one adapter-visible import in
            // positive examples. That import is the semantic file
            // context that keeps local receiver names from becoming
            // global API matches.
            if !example.expect_no_match && !signals.is_empty() {
                let mut has_import_for_signal = false;
                for file_id in ws.db().global_index().all_files() {
                    let Some(import_index) = ws.db().import_index(file_id) else {
                        continue;
                    };
                    for spec in &import_index.imports {
                        example_imports.insert(spec.module.clone());
                    }
                    if import_index.imports.iter().any(|spec| {
                        signals
                            .iter()
                            .any(|sig| crate::pkg::import_matches_package(&spec.module, sig))
                    }) {
                        has_import_for_signal = true;
                        break;
                    }
                }
                if !has_import_for_signal {
                    push_validation_issue(
                        &mut issues,
                        "warning",
                        "match-example-missing-import",
                        Some(rule),
                        &format!(
                            "example `{}` does not import any of {:?} — the rule's \
                             receiver-agnostic regex package gate cannot fire on this example",
                            example.name.as_deref().unwrap_or("<unnamed>"),
                            signals
                        ),
                    );
                }
            }
            for (index, seen) in &mut arg_tainted_index_seen {
                if !*seen && crate::matcher::rule_example_has_arg_index(&ws, rule, *index) {
                    *seen = true;
                }
            }
            let match_texts = match_example_owner_texts(pack, rule, &ws);
            if example.expect_no_match {
                if example.expect_no_match_text.is_empty() {
                    if !match_texts.is_empty() {
                        let got = match_texts.join(", ");
                        push_validation_issue(
                            &mut issues,
                            "warning",
                            "match-example-unexpected-match",
                            Some(rule),
                            &format!(
                                "negative example `{}` unexpectedly matched owner rule with [{got}]",
                                example.name.as_deref().unwrap_or("<unnamed>")
                            ),
                        );
                    }
                } else {
                    for unexpected in &example.expect_no_match_text {
                        if match_texts.iter().any(|m| m == unexpected) {
                            push_validation_issue(
                                &mut issues,
                                "warning",
                                "match-example-unexpected-match",
                                Some(rule),
                                &format!(
                                    "negative example `{}` unexpectedly matched text `{unexpected}`",
                                    example.name.as_deref().unwrap_or("<unnamed>")
                                ),
                            );
                        }
                    }
                }
                continue;
            }
            if match_texts.is_empty() {
                // Rules with taint-dependent constraints require live
                // taint analysis to fire; the static
                // `match_example_owner_texts` check cannot satisfy
                // them. The same skip is applied by the
                // `declared_rule_match_examples_fire` test
                // (`rule_uses_arg_tainted`); apply it here too so
                // the validator and the test agree on which
                // examples are statically checkable.
                if rule_has_taint_dependent_constraint(rule) {
                    continue;
                }
                push_validation_issue(
                    &mut issues,
                    "warning",
                    "match-example-owner-miss",
                    Some(rule),
                    &format!(
                        "example `{}` produced no match for its owner rule",
                        example.name.as_deref().unwrap_or("<unnamed>")
                    ),
                );
                continue;
            }
            for expected in &example.expect_match_text {
                if !match_texts.iter().any(|m| m == expected) {
                    let got = match_texts.join(", ");
                    push_validation_issue(
                        &mut issues,
                        "warning",
                        "match-example-text-miss",
                        Some(rule),
                        &format!(
                            "example `{}` expected match_text `{expected}`, got [{got}]",
                            example.name.as_deref().unwrap_or("<unnamed>")
                        ),
                    );
                }
            }
            if rule.enabled && !rule_has_taint_dependent_constraint(rule) {
                enabled_examples.push(ValidationExample {
                    owner: rule,
                    example,
                    ws,
                });
            }
        }
        // Reached only for `rule.enabled == true` (see the early
        // `continue` above). Arg-tainted index bounds can only be
        // populated by the live matcher; rules whose primary
        // `arg_tainted` constraint cannot fire on static examples
        // would always emit false-positive
        // `arg-tainted-index-out-of-range` errors. Skip those.
        if !rule_has_taint_dependent_constraint(rule) {
            validate_arg_tainted_index_bounds(rule, &arg_tainted_index_seen, &mut issues);
        }
        validate_constraint_coverage(rule, &mut issues);
        validate_regex_package_signals_match_example_imports(rule, &example_imports, &mut issues);
    }

    let enabled_rules: Vec<_> = rules.iter().copied().filter(|rule| rule.enabled).collect();
    let mut peer_groups: BTreeMap<(String, RuleKind, String), Vec<&Rule>> = BTreeMap::new();
    for rule in &enabled_rules {
        peer_groups
            .entry((rule.language.clone(), rule.kind, rule_match_target_key(rule)))
            .or_default()
            .push(*rule);
    }
    for prepared in &enabled_examples {
        let owner = prepared.owner;
        let peer_key = (owner.language.clone(), owner.kind, rule_match_target_key(owner));
        let peers = peer_groups.get(&peer_key).cloned().unwrap_or_default();
        for hit in crate::matcher::match_rules_against_facts(&prepared.ws, &peers) {
            if hit.rule_id == owner.id || !id_seen.contains(hit.rule_id.as_str()) {
                continue;
            }
            push_validation_issue(
                &mut issues,
                "warning",
                "match-example-collision",
                Some(owner),
                &format!(
                    "example `{}` also matched {} at {}:{} text `{}`; merge duplicate rules or tighten the match shape",
                    prepared.example.name.as_deref().unwrap_or("<unnamed>"),
                    hit.rule_id,
                    hit.file,
                    hit.line,
                    hit.match_text
                ),
            );
        }
    }

    let errors = issues.iter().filter(|issue| issue.level == "error").count();
    let warnings = issues.iter().filter(|issue| issue.level == "warning").count();
    PackValidationReport {
        valid: errors == 0,
        rule_count: rules.len(),
        enabled_rule_count,
        disabled_rule_count,
        disabled_waiting_reenable_count,
        disabled_reason_counts,
        example_count,
        enabled_example_count,
        errors,
        warnings,
        issues,
    }
}

fn match_example_owner_texts(pack: &Rulepack, rule: &Rule, ws: &Workspace) -> Vec<String> {
    if rule.kind == RuleKind::Sink && rule_has_taint_dependent_constraint(rule) {
        return match_arg_tainted_example_owner_texts(pack, rule, ws);
    }
    crate::matcher::match_rule_against_facts(ws, rule)
        .into_iter()
        .map(|hit| hit.match_text)
        .collect()
}

fn match_arg_tainted_example_owner_texts(pack: &Rulepack, rule: &Rule, ws: &Workspace) -> Vec<String> {
    let report = run_taint_analysis(
        ws,
        pack,
        TaintAnalysisOptions {
            sink: Some(format!("^{}$", regex::escape(&rule.id))),
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    );
    let Ok(report) = report else {
        return Vec::new();
    };
    let mut texts = Vec::new();
    for finding in report.findings {
        if finding.finding.sink.rule_id == rule.id {
            texts.push(finding.finding.sink.text);
        }
        for sink in finding.additional_sinks {
            if sink.rule_id == rule.id {
                texts.push(sink.text);
            }
        }
    }
    texts
}

fn rule_has_taint_dependent_constraint(rule: &Rule) -> bool {
    rule.constraints.iter().any(|constraint| {
        matches!(
            constraint,
            ConstraintKind::ArgTainted { .. }
                | ConstraintKind::AnyArgTainted { .. }
                | ConstraintKind::ReceiverTainted { .. }
        )
    })
}

fn validate_arg_tainted_index_bounds(
    rule: &Rule,
    arg_tainted_index_seen: &BTreeMap<u32, bool>,
    issues: &mut Vec<PackValidationIssue>,
) {
    for (index, seen) in arg_tainted_index_seen {
        if !*seen {
            push_validation_issue(
                issues,
                "error",
                "arg-tainted-index-out-of-range",
                Some(rule),
                &format!("arg_tainted index `{index}` is out of range across every match_examples entry"),
            );
        }
    }
}

fn validate_constraint_coverage(rule: &Rule, issues: &mut Vec<PackValidationIssue>) {
    if rule.constraints.is_empty() {
        return;
    }
    if !rule.enabled && rule.match_examples.is_empty() {
        return;
    }
    let has_positive_example = rule.match_examples.iter().any(|example| !example.expect_no_match);
    let has_negative_example = rule.match_examples.iter().any(|example| example.expect_no_match);
    let mut checked = BTreeSet::new();
    for constraint in &rule.constraints.0 {
        if !checked.insert(constraint.name()) {
            continue;
        }
        if constraint.is_discriminating() {
            if !has_positive_example {
                push_validation_issue(
                    issues,
                    "error",
                    "constraint-not-exercised",
                    Some(rule),
                    &format!(
                        "discriminating constraint `{}` requires at least one positive match_examples entry",
                        constraint.name()
                    ),
                );
            }
            if !has_negative_example {
                push_validation_issue(
                    issues,
                    "error",
                    "constraint-not-exercised",
                    Some(rule),
                    &format!(
                        "discriminating constraint `{}` requires at least one negative match_examples entry",
                        constraint.name()
                    ),
                );
            }
        } else if !has_positive_example {
            push_validation_issue(
                issues,
                "error",
                "constraint-not-exercised",
                Some(rule),
                &format!(
                    "structural constraint `{}` requires at least one positive match_examples entry",
                    constraint.name()
                ),
            );
        }
    }
}

fn validate_regex_package_signals_match_example_imports(
    rule: &Rule,
    example_imports: &BTreeSet<String>,
    issues: &mut Vec<PackValidationIssue>,
) {
    let has_signal = !rule.packages.is_empty() || !rule.imports.is_empty() || !rule.modules.is_empty();
    if !rule.enabled
        || !has_signal
        || example_imports.is_empty()
        || !crate::matcher::rule_regex_requires_package_signal(rule)
    {
        return;
    }
    let signals: Vec<&str> = rule
        .packages
        .iter()
        .chain(rule.imports.iter())
        .chain(rule.modules.iter())
        .map(String::as_str)
        .filter(|signal| !signal.is_empty())
        .collect();
    if signals.iter().any(|signal| {
        example_imports
            .iter()
            .any(|imported| crate::pkg::import_matches_package(imported, signal))
    }) {
        return;
    }
    let imports = example_imports.iter().cloned().collect::<Vec<_>>().join(", ");
    push_validation_issue(
        issues,
        "warning",
        "package-signal-not-adapter-visible",
        Some(rule),
        &format!(
            "none of the rule's package/import/module signals {:?} match adapter-emitted imports \
             in match_examples; use the ImportSpec.module form seen in examples. Example imports: [{imports}]",
            signals
        ),
    );
}

fn validate_rule_metadata(rule: &Rule, issues: &mut Vec<PackValidationIssue>) {
    if rule.language.trim().is_empty() {
        push_validation_issue(
            issues,
            "error",
            "missing-language",
            Some(rule),
            "rule language is empty",
        );
    }
    if !rule_id_is_dotted_lowercase(&rule.id) {
        push_validation_issue(
            issues,
            "error",
            "invalid-rule-id",
            Some(rule),
            "rule id must be dotted lowercase snake_case segments",
        );
    }
    let description = rule.description.trim();
    if description.len() < 15 {
        push_validation_issue(
            issues,
            "error",
            "thin-description",
            Some(rule),
            "description must explain the API shape and security consequence",
        );
    }
    if rule.kind == RuleKind::Source && rule.trust.is_none() {
        push_validation_issue(
            issues,
            "error",
            "missing-source-trust",
            Some(rule),
            "source rules must declare trust",
        );
    }
    if rule.kind == RuleKind::Sink && rule.cwe.is_empty() {
        push_validation_issue(
            issues,
            "error",
            "missing-cwe",
            Some(rule),
            "sink rules must declare CWE",
        );
    }
    if rule.enabled && rule.disabled_reason.is_some() {
        push_validation_issue(
            issues,
            "error",
            "enabled-rule-disabled-reason",
            Some(rule),
            "enabled rules must not declare disabled_reason",
        );
    }
    if !rule.enabled && rule.disabled_reason.is_none() {
        push_validation_issue(
            issues,
            "error",
            "missing-disabled-reason",
            Some(rule),
            "disabled rules must declare disabled_reason.code",
        );
    }
    let arg_tainted_constraints = rule
        .constraints
        .iter()
        .filter(|constraint| matches!(constraint, ConstraintKind::ArgTainted { .. }))
        .count();
    if arg_tainted_constraints > 0 && rule.kind == RuleKind::Sanitizer {
        push_validation_issue(
            issues,
            "error",
            "arg-tainted-in-sanitizer",
            Some(rule),
            "sanitizer rules cannot use arg_tainted; sanitizers must not decide taint propagation",
        );
    }
    if arg_tainted_constraints > 0
        && rule.kind == RuleKind::Source
        && arg_tainted_constraints == rule.constraints.0.len()
    {
        push_validation_issue(
            issues,
            "warning",
            "arg-tainted-source-redundant",
            Some(rule),
            "source rule uses only arg_tainted, which is redundant with normal source taint",
        );
    }
    if rule.enabled {
        match rule.kind {
            RuleKind::Source => {
                if rule.tag.is_none() {
                    push_validation_issue(
                        issues,
                        "error",
                        "missing-tag",
                        Some(rule),
                        "enabled source is missing tag",
                    );
                }
                if rule.trust.is_none() {
                    push_validation_issue(
                        issues,
                        "error",
                        "missing-trust",
                        Some(rule),
                        "enabled source is missing trust",
                    );
                }
            }
            RuleKind::Sink => {
                if rule.tag.is_none() {
                    push_validation_issue(
                        issues,
                        "error",
                        "missing-tag",
                        Some(rule),
                        "enabled sink is missing tag",
                    );
                }
                if rule.severity.is_none() {
                    push_validation_issue(
                        issues,
                        "error",
                        "missing-severity",
                        Some(rule),
                        "enabled sink is missing severity",
                    );
                }
            }
            RuleKind::Sanitizer => {
                if rule.tag.is_none() {
                    push_validation_issue(
                        issues,
                        "error",
                        "missing-tag",
                        Some(rule),
                        "enabled sanitizer is missing tag",
                    );
                }
            }
        }
    }
    validate_rule_regexes(rule, issues);
    validate_no_hardcoded_receiver_regex(rule, issues);
    validate_receiver_agnostic_regex_has_package_gate(rule, issues);
    validate_taint_semantics(rule, issues);
    validate_packages_not_maven_artifacts(rule, issues);
    validate_yaml_language_field(rule, issues);
}

fn validate_taint_semantics(rule: &Rule, issues: &mut Vec<PackValidationIssue>) {
    let Some(semantics) = rule.taint_semantics.as_ref() else {
        return;
    };
    if semantics.taint_receiver_from_args {
        if rule.kind != RuleKind::Sink {
            push_validation_issue(
                issues,
                "error",
                "invalid-taint-semantics",
                Some(rule),
                "taint_semantics.taint_receiver_from_args is only valid on sink rules",
            );
        }
        let valid_attribute = rule
            .match_spec
            .callee
            .as_ref()
            .and_then(|target| target.attribute.as_ref())
            .is_some_and(|attribute| attribute.len() >= 2);
        if !valid_attribute {
            push_validation_issue(
                issues,
                "error",
                "invalid-taint-semantics",
                Some(rule),
                "taint_semantics.taint_receiver_from_args requires a structured callee.attribute with receiver type and method",
            );
        }
    }
    if !semantics.source_output_args.is_empty() && rule.kind != RuleKind::Source {
        push_validation_issue(
            issues,
            "error",
            "invalid-taint-semantics",
            Some(rule),
            "taint_semantics.source_output_args is only valid on source rules",
        );
    }
    if !semantics.call_result_passthrough_args.is_empty() && rule.kind != RuleKind::Sanitizer {
        push_validation_issue(
            issues,
            "error",
            "invalid-taint-semantics",
            Some(rule),
            "taint_semantics.call_result_passthrough_args is only valid on sanitizer/passthrough rules",
        );
    }
    if semantics.call_result_passthrough_receiver && rule.kind != RuleKind::Sanitizer {
        push_validation_issue(
            issues,
            "error",
            "invalid-taint-semantics",
            Some(rule),
            "taint_semantics.call_result_passthrough_receiver is only valid on sanitizer/passthrough rules",
        );
    }
    for flow in &semantics.output_arg_flows {
        if flow.value_start_arg_index.is_none() && flow.value_arg_indices.is_empty() {
            push_validation_issue(
                issues,
                "error",
                "invalid-taint-semantics",
                Some(rule),
                "taint_semantics.output_arg_flows entries require value_start_arg_index or value_arg_indices",
            );
        }
        if flow.value_arg_indices.contains(&flow.output_arg_index) {
            push_validation_issue(
                issues,
                "error",
                "invalid-taint-semantics",
                Some(rule),
                "taint_semantics.output_arg_flows value_arg_indices must not include output_arg_index",
            );
        }
    }
    if semantics.clean_output_overwrite.is_some() && rule.kind != RuleKind::Sanitizer {
        push_validation_issue(
            issues,
            "error",
            "invalid-taint-semantics",
            Some(rule),
            "taint_semantics.clean_output_overwrite is only valid on sanitizer rules",
        );
    }
}

fn validate_rule_regexes(rule: &Rule, issues: &mut Vec<PackValidationIssue>) {
    let targets = [
        ("match.callee.regex", rule.match_spec.callee.as_ref()),
        ("match.target.regex", rule.match_spec.target.as_ref()),
    ];
    for (field, target) in targets {
        let Some(regex) = target.and_then(|target| target.regex.as_deref()) else {
            continue;
        };
        if let Err(error) = Regex::new(regex) {
            push_validation_issue(
                issues,
                "error",
                "match-example-regex-invalid",
                Some(rule),
                &format!("{field} `{regex}` is not a valid regex: {error}"),
            );
        }
    }
    for constraint in &rule.constraints.0 {
        let regex = match constraint {
            crate::rule::ConstraintKind::ArgMatchesRegex { arg_matches_regex } => {
                Some(("constraints.arg_matches_regex", arg_matches_regex.regex.as_str()))
            }
            crate::rule::ConstraintKind::ArgNotMatchesRegex {
                arg_not_matches_regex,
            } => Some((
                "constraints.arg_not_matches_regex",
                arg_not_matches_regex.regex.as_str(),
            )),
            crate::rule::ConstraintKind::AnyArgMatchesRegex {
                any_arg_matches_regex,
            } => Some((
                "constraints.any_arg_matches_regex",
                any_arg_matches_regex.as_str(),
            )),
            crate::rule::ConstraintKind::ReceiverTypeIn { .. }
            | crate::rule::ConstraintKind::SecondArgEquals { .. }
            | crate::rule::ConstraintKind::ArgEquals { .. }
            | crate::rule::ConstraintKind::KeywordArgEquals { .. }
            | crate::rule::ConstraintKind::ArgTainted { .. }
            | crate::rule::ConstraintKind::ReceiverTainted { .. }
            | crate::rule::ConstraintKind::AnyArgTainted { .. }
            | crate::rule::ConstraintKind::FormatArgIndex { .. }
            | crate::rule::ConstraintKind::Namespace { .. }
            | crate::rule::ConstraintKind::TopLevel { .. }
            | crate::rule::ConstraintKind::ArgCount { .. }
            | crate::rule::ConstraintKind::MinArgs { .. }
            | crate::rule::ConstraintKind::MaxArgs { .. }
            | crate::rule::ConstraintKind::SameReceiverCallCountAtLeast { .. }
            | crate::rule::ConstraintKind::ArgLt { .. }
            | crate::rule::ConstraintKind::ArgLe { .. }
            | crate::rule::ConstraintKind::ArgGt { .. }
            | crate::rule::ConstraintKind::ArgGe { .. }
            | crate::rule::ConstraintKind::RequiresRuntimeType { .. }
            | crate::rule::ConstraintKind::EnclosingDecoratorIn { .. }
            | crate::rule::ConstraintKind::MustAlias { .. }
            | crate::rule::ConstraintKind::RequiresState { .. } => None,
        };
        let Some((field, regex)) = regex else {
            continue;
        };
        if let Err(error) = Regex::new(regex) {
            push_validation_issue(
                issues,
                "error",
                "match-example-regex-invalid",
                Some(rule),
                &format!("{field} `{regex}` is not a valid regex: {error}"),
            );
        }
    }
}

fn validate_no_hardcoded_receiver_regex(rule: &Rule, issues: &mut Vec<PackValidationIssue>) {
    if !rule.enabled {
        return;
    }
    // Package-qualified regexes such as `^lodash\.escape$` or
    // `^bleach\.clean$` are legitimate only when the rule declares the
    // package/import/module signal that lets the matcher verify file
    // context. Local receiver names should be represented by semantic
    // receiver types or receiver-agnostic regexes gated by imports.
    if rule.match_spec.kind != MatchKind::Call && rule.match_spec.kind != MatchKind::Read {
        return;
    }
    let Some(regex) = rule
        .match_spec
        .callee
        .as_ref()
        .and_then(|callee| callee.regex.as_deref())
        .or_else(|| {
            rule.match_spec
                .target
                .as_ref()
                .and_then(|target| target.regex.as_deref())
        })
    else {
        return;
    };
    let Some(receiver) = lowercase_receiver_token_from_regex(regex) else {
        return;
    };
    // Genuine module/namespace receivers must be declared by the rule
    // itself through packages/imports/modules. The validator should
    // never carry a central language-specific list of "known good"
    // receiver tokens; that recreates the same name-based shortcut
    // the engine avoids at runtime.
    if receiver_token_is_declared_package_signal(rule, &receiver) {
        return;
    }
    push_validation_issue(
        issues,
        "error",
        "hardcoded-receiver-regex",
        Some(rule),
        &format!(
            "`regex:` `{regex}` hardcodes lowercase receiver `{receiver}`. Use a receiver-agnostic \
             local-identifier regex (e.g. `^[A-Za-z_$][A-Za-z0-9_$]*\\.method$`) plus adapter-visible \
             package/import/module signals, or use a structured `attribute:` rule when the receiver is \
             a Module/Type."
        ),
    );
}

/// Catch the failure mode the JS/TS receiver-agnostic regex pass hit:
/// a rule whose `regex:` matches `<any-receiver>.method` but that has
/// NO `packages:`/`imports:`/`modules:` declaration, so the regex
/// fires in every file regardless of whether the framework is even
/// imported. The matcher cannot apply a per-file gate to bare regex
/// rules without a package signal — the validator must.
fn validate_receiver_agnostic_regex_has_package_gate(rule: &Rule, issues: &mut Vec<PackValidationIssue>) {
    if !rule.enabled {
        return;
    }
    if matches!(rule.kind, RuleKind::Sanitizer) {
        return;
    }
    let Some(regex) = rule
        .match_spec
        .callee
        .as_ref()
        .and_then(|callee| callee.regex.as_deref())
        .or_else(|| {
            rule.match_spec
                .target
                .as_ref()
                .and_then(|target| target.regex.as_deref())
        })
    else {
        return;
    };
    if !regex_prefix_is_receiver_agnostic(regex) {
        return;
    }
    let has_signal = !rule.packages.is_empty() || !rule.imports.is_empty() || !rule.modules.is_empty();
    if has_signal {
        return;
    }
    push_validation_issue(
        issues,
        "error",
        "receiver-agnostic-regex-without-package-gate",
        Some(rule),
        &format!(
            "`regex:` `{regex}` accepts any receiver but the rule has no `packages:` / `imports:` \
             / `modules:` declaration. Without a package gate the regex collides with peer rules' \
             match_examples in unrelated files. Add a `packages:` (or `imports:` / `modules:`) \
             entry naming the framework whose API this rule classifies."
        ),
    );
}

/// Catch package signals whose syntax can never match what the
/// language adapter emits in `ImportSpec.module`. Runtime package
/// context checks consult the adapter's import index — a signal that
/// uses package-manager distribution syntax (Maven `groupId-artifactId`,
/// PyPI `python-jose`, Cargo `percent-encoding`, Swift `async-http-client`)
/// instead of the adapter-visible import string is a silent context-gate
/// failure: the rule loads, the matcher can't fire it on real files,
/// and previously the validator only noticed when an example imported
/// the wrong shape. Fail-fast at load time, language-aware.
///
/// Languages NOT listed here (C/C++/ObjC, Go, JS/TS, Lua, Ruby, PHP,
/// Solidity, Erlang) legitimately use hyphens in their import strings
/// — npm `sanitize-html`, Lua `lua-resty-string`, Ruby `rest-client`,
/// Go path segments, PHP composer slugs — so the syntactic check
/// would be a false positive for them. Their import-vs-package drift
/// is caught by the slower adapter-visible-import warning instead.
fn validate_packages_not_maven_artifacts(rule: &Rule, issues: &mut Vec<PackValidationIssue>) {
    for signal_field in [&rule.packages, &rule.imports, &rule.modules] {
        for signal in signal_field {
            let Some(reason) = package_signal_distro_smell(&rule.language, signal) else {
                continue;
            };
            push_validation_issue(
                issues,
                "error",
                "package-is-distribution-name",
                Some(rule),
                &format!(
                    "`{signal}` is a {reason}, not a string the {} adapter sees in `import` / \
                     `use` / `require` statements. Runtime package context checks consult the \
                     adapter's import index — replace with the actual import-visible \
                     package/module string.",
                    rule.language
                ),
            );
        }
    }
}

/// Decide whether `signal` looks like a package-manager distribution
/// name rather than the import-visible string the adapter parses.
/// Returns a short reason fragment for the error message, or `None`
/// when the signal is well-formed for the language.
fn package_signal_distro_smell(language: &str, signal: &str) -> Option<&'static str> {
    if signal.is_empty() {
        return None;
    }
    match language {
        // JVM ecosystems: imports are dotted reverse-domain
        // (`org.springframework.web`); a token with no dot and a
        // hyphen is a Maven artifact coordinate (`spring-web`,
        // `gwt-user`). All-lowercase (or with digits) eliminates
        // false positives on real JVM names.
        "java" | "kotlin" | "scala" => {
            if signal.contains('.') || !signal.contains('-') {
                return None;
            }
            if signal
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Some("Maven artifact coordinate (groupId-artifactId)");
            }
            None
        }
        // Python imports never contain `-`. PyPI distributions like
        // `python-jose`, `argon2-cffi`, `flask-limiter` shouldn't
        // appear in `packages:`; the adapter only sees the import
        // string (`jose`, `argon2`, `flask_limiter`).
        //
        // Distros without a `-` but whose distribution name still
        // differs from the Python import name also count
        // (`pyyaml` → `yaml`, `beautifulsoup4` → `bs4`,
        // `protobuf` is OK because both names match,
        // `pillow` → `PIL`). Spotted by the table below; extend it
        // when a new distro/import mismatch surfaces in real
        // packs.
        "python" => {
            if signal.contains('-') {
                return Some("PyPI distribution name (Python imports never contain `-`)");
            }
            const PYPI_NON_IMPORT_DISTROS: &[&str] = &[
                "pyyaml",         // → yaml
                "beautifulsoup4", // → bs4
                "pillow",         // → PIL
                "msgpack-python", // pre-2.0; → msgpack (also has `-`)
                "python3-saml",   // → onelogin.saml2
                "pycryptodome",   // → Crypto (top-level shim)
            ];
            if PYPI_NON_IMPORT_DISTROS.contains(&signal) {
                return Some("PyPI distribution name whose Python import differs (e.g. `pyyaml` → `yaml`)");
            }
            None
        }
        // Rust crates can carry hyphens in `Cargo.toml` but
        // `extern crate` / `use` resolves them to underscored
        // identifiers (`extern crate percent_encoding;`). The
        // adapter sees `percent_encoding`, not `percent-encoding`,
        // so signals naming the Cargo distro form silently fail.
        "rust" => {
            if signal.contains('-') {
                Some("Cargo crate distribution name (Rust `use` paths use `_`, not `-`)")
            } else {
                None
            }
        }
        // Swift imports are CamelCase module names
        // (`import AsyncHTTPClient`, `import Foundation`). SwiftPM
        // package names like `async-http-client` map to a different
        // import token; the adapter only sees the module form.
        "swift" => {
            if signal.contains('-') {
                Some("SwiftPM distribution name (Swift module imports are CamelCase, no `-`)")
            } else {
                None
            }
        }
        // Perl modules use `Foo::Bar` syntax in `use`; CPAN
        // distribution names have hyphens (`Net-LDAP`) but the
        // import is `Net::LDAP`. Hyphenated signals are wrong.
        "perl" => {
            if signal.contains('-') {
                Some("CPAN distribution name (Perl `use` is `Foo::Bar`, never `Foo-Bar`)")
            } else {
                None
            }
        }
        // Dart packages on pub.dev are required to be snake_case;
        // hyphens are illegal in package names AND in dart imports.
        "dart" => {
            if signal.contains('-') {
                Some("non-snake_case package name (Dart pub packages disallow `-`)")
            } else {
                None
            }
        }
        // C/C++/ObjC, Go, JS/TS, Lua, Ruby, PHP, Solidity, Erlang
        // all permit hyphens in adapter-visible import strings; the
        // syntactic check would mis-flag legitimate usage.
        _ => None,
    }
}

fn lowercase_receiver_token_from_regex(regex: &str) -> Option<String> {
    let rest = regex.trim().strip_prefix('^')?;
    let (receiver, after_receiver) = if let Some(grouped) = rest.strip_prefix('(') {
        let end = grouped.find(')')?;
        (&grouped[..end], &grouped[end + 1..])
    } else {
        let dot = rest.find("\\.")?;
        (&rest[..dot], &rest[dot..])
    };
    if receiver.is_empty() || !after_receiver.starts_with("\\.") {
        return None;
    }
    if !receiver.split('|').all(hardcoded_lowercase_receiver_token) {
        return None;
    }
    Some(receiver.to_string())
}

/// True when the regex prefix is the receiver-agnostic identifier
/// pattern `^[A-Za-z_$][A-Za-z0-9_$]*\.` (i.e. it deliberately
/// matches any local variable name as the leftmost segment).
fn regex_prefix_is_receiver_agnostic(regex: &str) -> bool {
    let rest = regex.trim().strip_prefix('^').unwrap_or(regex);
    // Accept either bracket or grouped form. Both end with `]*\.` or
    // `]+\.` and start with `[`.
    rest.starts_with("[A-Za-z_")
        && rest.contains("]*\\.")
        && (rest.contains("A-Za-z0-9_") || rest.contains("a-zA-Z0-9_"))
}

/// Returns true when `token` is accounted for by the rule's own
/// declared import/package/module metadata. This keeps validator
/// behavior semantic and rule-local instead of relying on a central
/// per-language list of namespace names.
fn receiver_token_is_declared_package_signal(rule: &Rule, token: &str) -> bool {
    let token = token.trim();
    if token.is_empty() {
        return false;
    }
    rule.packages
        .iter()
        .chain(rule.imports.iter())
        .chain(rule.modules.iter())
        .any(|signal| package_signal_matches_receiver_token(signal, token))
}

fn package_signal_matches_receiver_token(signal: &str, token: &str) -> bool {
    let signal = signal.trim();
    if signal.is_empty() {
        return false;
    }
    signal == token
        || signal
            .rsplit(&['.', '/', ':', '\\', '-'][..])
            .next()
            .is_some_and(|tail| tail == token)
}

fn hardcoded_lowercase_receiver_token(token: &str) -> bool {
    let mut chars = token.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn rule_match_target_key(rule: &Rule) -> String {
    let target = match rule.match_spec.kind {
        MatchKind::Call | MatchKind::New | MatchKind::Missing => rule.match_spec.callee.as_ref(),
        MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param => {
            rule.match_spec.target.as_ref()
        }
    };
    let Some(target) = target else {
        return "<empty>".to_string();
    };
    if let Some(attribute) = &target.attribute {
        return format!("attribute:{}", attribute.join("."));
    }
    if let Some(name) = &target.name {
        return format!("name:{name}");
    }
    if let Some(regex) = &target.regex {
        return format!("regex:{regex}");
    }
    if let Some(annotation) = &target.annotation {
        return format!("annotation:{annotation}");
    }
    "<empty>".to_string()
}

fn validate_yaml_language_field(rule: &Rule, issues: &mut Vec<PackValidationIssue>) {
    let Ok(text) = std::fs::read_to_string(&rule.source_path) else {
        push_validation_issue(
            issues,
            "error",
            "unreadable-rule-file",
            Some(rule),
            "rule source file could not be read",
        );
        return;
    };
    let needle = format!("- id: {}", rule.id);
    let Some(rule_block_start) = text.find(&needle) else {
        push_validation_issue(
            issues,
            "error",
            "rule-body-not-found",
            Some(rule),
            "rule id was not found in its source YAML file",
        );
        return;
    };
    let after = &text[rule_block_start + needle.len()..];
    let block_end = after.find("\n- id: ").unwrap_or(after.len());
    let block = &after[..block_end];
    let want_line = format!("\n  language: {}\n", rule.language);
    if !block.contains(&want_line) {
        push_validation_issue(
            issues,
            "error",
            "missing-yaml-language",
            Some(rule),
            &format!("rule YAML must include `language: {}`", rule.language),
        );
    }
}

fn rule_id_is_dotted_lowercase(id: &str) -> bool {
    let mut parts = id.split('.');
    let Some(first) = parts.next() else { return false };
    if first.is_empty() || !segment_is_lower_snake(first, true) {
        return false;
    }
    let mut saw_tail = false;
    for part in parts {
        saw_tail = true;
        if part.is_empty() || !segment_is_lower_snake(part, false) {
            return false;
        }
    }
    saw_tail
}

fn segment_is_lower_snake(segment: &str, require_alpha_first: bool) -> bool {
    let mut chars = segment.chars();
    if require_alpha_first {
        let Some(first) = chars.next() else { return false };
        if !first.is_ascii_lowercase() {
            return false;
        }
    }
    segment
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn default_example_path(language: &str, registry: &LanguageRegistry) -> String {
    let ext = registry
        .all()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == language)
        .and_then(|adapter| adapter.file_extensions().first().copied())
        .unwrap_or("txt");
    format!("example.{ext}")
}

fn example_workspace(
    language: &str,
    path: Option<&str>,
    code: &str,
    registry: Arc<LanguageRegistry>,
) -> Workspace {
    let ws = Workspace::new(registry.clone());
    let path = path
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| default_example_path(language, &registry));
    ws.vfs().write(path, Arc::<str>::from(code));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn push_validation_issue(
    issues: &mut Vec<PackValidationIssue>,
    level: &'static str,
    code: &'static str,
    rule: Option<&Rule>,
    message: &str,
) {
    issues.push(PackValidationIssue {
        level,
        code,
        rule_id: rule.map(|r| r.id.clone()),
        path: rule.map(|r| r.source_path.clone()),
        message: message.to_string(),
    });
}

/// Run a per-file match phase: emit `PhaseStarted { label, total_files }`,
/// tick once per file, then `PhaseFinished`. Used internally by
/// `run_taint_analysis_with_phase_progress` so each matching pass shows
/// up as one progress bar with a known length.
fn gather_matches_phased<F>(
    ws: &Workspace,
    rules: &[&Rule],
    label: &'static str,
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
    let matches = match_rules_against_facts_with_progress(ws, rules, || {
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
    chain_names: Vec<String>,
    chain_precision: Precision,
    taint_path: Vec<TaintPropagationStep>,
    sink_tainted_args: Vec<TaintedArgInfo>,
}

fn build_call_evidence(
    ws: &Workspace,
    trace_index: &AHashMap<u64, &TaintedCallEdge>,
    canonical_chain_index: &CanonicalChainIndex,
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
    let records = lineage_records_for_call_indexed(trace_index, call)?;
    let primary = chain_funcs_for_lineage(&records, source_func, call.caller)?;
    // Chain-quality upgrade: when the lineage walk anchored on
    // `parent_trace_id` goes through synthetic edges (Phase 3c field-flow
    // stitches, Phase 3d receiver-method propagation, or Return back-edges),
    // prefer an equivalent canonical call sequence with fewer synthetic hops.
    let chain_funcs =
        rewrite_chain_with_canonical_path(primary, canonical_chain_index, source_func, call.caller);
    let chain_precision = chain_precision_for_records(&records);
    if !chain_precision.is_semantic() {
        return None;
    }
    let taint_path = taint_path_for_lineage(ws, &records, Some(call));
    let chain_names = chain_names_for_path(ws, &chain_funcs)?;
    let sink_tainted_args: Vec<TaintedArgInfo> = call
        .tainted_args
        .iter()
        .map(|arg| TaintedArgInfo {
            index: arg.index,
            value_text: arg.value_text.clone(),
        })
        .collect();
    Some(CallEvidence {
        chain_funcs,
        chain_names,
        chain_precision,
        taint_path,
        sink_tainted_args,
    })
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
struct CanonicalChainIndex {
    adjacency: AHashMap<FuncId, Vec<(FuncId, bool)>>,
    edge_has_any: AHashSet<(FuncId, FuncId)>,
    edge_has_real: AHashSet<(FuncId, FuncId)>,
}

impl CanonicalChainIndex {
    fn new(records: &[TaintedCallEdge]) -> Self {
        let mut edge_synthetic: AHashMap<(FuncId, FuncId), bool> = AHashMap::default();
        let mut edge_has_any = AHashSet::default();
        let mut edge_has_real = AHashSet::default();
        for record in records {
            let is_synthetic = edge_is_synthetic(record);
            let edge = (record.caller, record.callee);
            edge_has_any.insert(edge);
            if !is_synthetic {
                edge_has_real.insert(edge);
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
        }
    }
}

fn rewrite_chain_with_canonical_path(
    primary: Vec<FuncId>,
    index: &CanonicalChainIndex,
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

fn edge_is_synthetic(record: &TaintedCallEdge) -> bool {
    record
        .tainted_args
        .first()
        .map(|arg| arg.index == usize::MAX || arg.index == 255)
        .unwrap_or(false)
}

fn chain_synth_count(chain: &[FuncId], index: &CanonicalChainIndex) -> usize {
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
    index: &CanonicalChainIndex,
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

fn propagation_step_for_edge(ws: &Workspace, record: &TaintedCallEdge) -> Option<TaintPropagationStep> {
    if record.caller == record.callee {
        return None;
    }
    let (file, line, column) = resolve_span_location(ws, record.call_span);
    let caller = func_display_name(ws, record.caller);
    let callee = func_display_name(ws, record.callee);
    let same_name = caller == callee;
    let caller = if same_name {
        func_display_name_with_site(ws, record.caller)
    } else {
        caller
    };
    let callee = if same_name {
        func_display_name_with_site(ws, record.callee)
    } else {
        callee
    };
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

fn propagation_step_for_terminal_call(ws: &Workspace, call: &TaintedCall) -> TaintPropagationStep {
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
    let caller = func_display_name(ws, call.caller);
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
    let mut path: Vec<TaintPropagationStep> = records
        .iter()
        .filter_map(|record| propagation_step_for_edge(ws, record))
        .collect();
    if let Some(call) = terminal_call {
        path.push(propagation_step_for_terminal_call(ws, call));
    }
    normalize_taint_path(path)
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
                bonsai_common::cached_span_map(decl.span.file, snapshot.version, snapshot.text.as_ref());
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
        let span_map = bonsai_common::cached_span_map(file, snapshot.version, snapshot.text.as_ref());
        let line_col = span_map.line_col(span.start);
        return (path, line_col.line, line_col.column);
    }
    (path, 0, 0)
}

/// Apply CLI `--files` / `--exclude-files` filters in place. Empty
/// `files` means "no positive filter — keep everything"; empty
/// `exclude` means "no negative filter — drop nothing".
fn filter_by_path(matches: &mut Vec<RuleMatch>, files: &[String], exclude: &[String]) {
    if !files.is_empty() {
        matches.retain(|rule_match| {
            files
                .iter()
                .any(|filter| path_filter_matches(&rule_match.file, filter))
        });
    }
    if !exclude.is_empty() {
        matches.retain(|rule_match| {
            !exclude
                .iter()
                .any(|filter| path_filter_matches(&rule_match.file, filter))
        });
    }
}

fn path_is_excluded(path: &str, exclude_files: &[String], exclude_tests: bool) -> bool {
    (exclude_tests && crate::finding::path_is_test_file(path))
        || exclude_files
            .iter()
            .any(|filter| path_filter_matches(path, filter))
}

fn taint_path_has_excluded_file(
    taint_path: &[TaintPropagationStep],
    exclude_files: &[String],
    exclude_tests: bool,
) -> bool {
    taint_path
        .iter()
        .any(|step| path_is_excluded(&step.file, exclude_files, exclude_tests))
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
    path_is_excluded(&candidate.source.file, exclude_files, exclude_tests)
        || taint_path_has_excluded_file(&candidate.taint_path, exclude_files, exclude_tests)
        || candidate.path.iter().any(|&func| {
            func_file_path(ws, func)
                .as_deref()
                .is_some_and(|path| path_is_excluded(path, exclude_files, exclude_tests))
        })
}

fn finding_has_excluded_path(finding: &Finding, exclude_files: &[String], exclude_tests: bool) -> bool {
    path_is_excluded(&finding.source.file, exclude_files, exclude_tests)
        || path_is_excluded(&finding.sink.file, exclude_files, exclude_tests)
        || taint_path_has_excluded_file(&finding.taint_path, exclude_files, exclude_tests)
        || finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| path_is_excluded(&sanitizer.file, exclude_files, exclude_tests))
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
        return path == trimmed
            || path.starts_with(&format!("{trimmed}/"))
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

/// Drop matches whose user-visible identity is identical to a
/// preceding entry. The matcher pipeline can emit the same call
/// site through more than one fact stream (e.g. an adapter that
/// resolves the enclosing decl ambiguously and registers the call
/// once under the function scope and once under the module scope).
/// Two byte-identical entries in the surface inventory table are
/// always a presentation bug. Identity here includes `match_text`
/// and `enclosing_fn` so genuinely distinct variants at the same
/// position (e.g. `response.headers` vs `response.headers.Location`
/// at a chained assignment) remain visible.
///
/// Only safe to call on inventory output — the taint-analysis
/// pipeline consumes the broader match stream where multiple
/// entries per call site carry distinct downstream context.
fn dedup_inventory_matches(matches: &mut Vec<RuleMatch>) {
    let mut seen: AHashSet<InventoryMatchIdentity> = AHashSet::new();
    matches.retain(|m| {
        seen.insert((
            m.language.clone(),
            m.file.clone(),
            m.line,
            m.column,
            m.rule_id.clone(),
            m.match_text.clone(),
            m.enclosing_fn.clone(),
        ))
    });
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
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, name) in &named_funcs {
        *counts.entry(name.clone()).or_default() += 1;
    }
    Some(
        named_funcs
            .into_iter()
            .map(|(func, name)| {
                if counts.get(&name).copied().unwrap_or_default() > 1 {
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

/// Join a chain into a key of the hop names as rendered. `chain_names_for_path`
/// suffixes repeated names with `@file:line` to keep the raw chain unique, but
/// that suffix never reaches the output — strip it so equivalently-rendered
/// chains share one key.
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
    for combined in &findings {
        let f = &combined.finding;
        if source_is_inferred(&f.source) {
            continue;
        }
        concrete_chains.insert(
            (f.language.clone(), f.chain_display.clone(), f.sink.rule_id.clone()),
            (),
        );
    }
    findings
        .into_iter()
        .filter(|combined| {
            let f = &combined.finding;
            // Concrete sources are never dropped here.
            if !source_is_inferred(&f.source) {
                return true;
            }
            // `class_field.inherited` is the synthesized-per-record-
            // component shape — always over-approximation, safe to
            // drop even without concrete coverage when the field
            // name mismatches the sink.
            let is_class_field = f.source.rule_id.contains(".class_field.inherited");
            // Other inferred shapes (e.g. `unreferenced_entry.param_N`)
            // may be the only upstream — only drop when a concrete
            // source already covers the same chain end-to-end.
            let same_chain_covered = {
                let key = (f.language.clone(), f.chain_display.clone(), f.sink.rule_id.clone());
                concrete_chains.contains_key(&key)
            };
            if !is_class_field && !same_chain_covered {
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
            let sink_arg_text = f
                .sink
                .tainted_args
                .iter()
                .map(|arg| arg.value_text.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let mentioned = sink_arg_text
                .split(|c: char| !(c == '_' || c.is_ascii_alphanumeric()))
                .any(|t| t == field);
            // Keep only the field-matching inferred sources; drop
            // the siblings that reached this chain via overtaint.
            mentioned
        })
        .collect()
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
    let src_is_http = src_token.contains("http") || src_token.contains("web") || src_token.contains("servlet");
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

/// True when two sink-side `FindingMatch`es refer to the exact same
/// call-site. Symmetric counterpart to [`same_source_site`].
fn same_sink_site(a: &FindingMatch, b: &FindingMatch) -> bool {
    a.rule_id == b.rule_id && a.file == b.file && a.line == b.line && a.column == b.column
}

fn combine_findings_by_source_flow(mut findings: Vec<FindingWithChain>) -> Vec<CombinedFindingWithChain> {
    let mut groups: Vec<CombinedFindingWithChain> = Vec::new();
    let mut index: AHashMap<String, usize> = AHashMap::new();

    // Stable-sort so that within each `(language, group_id,
    // representative_flow_id, chain, sink.rule_id)` bucket — which is
    // what `combined_finding_key` collapses into one group — the most
    // specific source becomes the primary one preserved on the merged
    // finding. The combiner's `merge_finding_into_group` keeps the
    // first-seen source as primary and demotes everything else to
    // `additional_sources`; without a deterministic preference,
    // co-tainted siblings can win and mis-label the chain (e.g. php's
    // `$_SERVER` taking precedence over the real `readline` source for
    // a cmd-injection finding even though both reach the sink through
    // the same `$envelope` container).
    //
    // Ordering criteria (lower is better → becomes primary):
    //   1. Sources whose `rule_id` starts with `entry-point.` or
    //      contains `.unreferenced_entry.` are inferred over-approxi-
    //      mations — push them to the back so a concrete source rule
    //      always wins when both are present in the same group.
    //   2. Sources whose `tag == sink.tag` are direct semantic matches
    //      (a `cli-input` source reaching a `command-injection` sink
    //      via the cmd-channel is more specific than a co-tainted
    //      `web-input` source threading through the same envelope).
    //   3. Otherwise: alphabetical by `rule_id`. Source rule IDs use
    //      `<lang>.<category>.<name>` so this prefers e.g.
    //      `php.source.readline` over `php.source.superglobal_server`,
    //      matching the "more specific / less broad" intuition.
    findings.sort_by(|a, b| {
        let inferred = |rule_id: &str| {
            rule_id.starts_with("entry-point.")
                || rule_id.contains(".unreferenced_entry.")
                || rule_id.contains(".class_field.inherited")
        };
        let inferred_a = inferred(&a.finding.source.rule_id);
        let inferred_b = inferred(&b.finding.source.rule_id);
        // Sort bucket MUST match `combined_finding_key`'s grouping
        // dimensions (language, group_id, sink site) — excluding
        // `representative_flow_id` / chain — so the inferred / source-rule
        // tiebreakers below decide the primary source WITHIN each merge
        // group rather than being pre-split by flow id.
        let bucket_a = (
            &a.finding.language,
            a.finding.group_id.as_deref().unwrap_or(""),
            &a.finding.sink.file,
            a.finding.sink.line,
            &a.finding.sink.rule_id,
        );
        let bucket_b = (
            &b.finding.language,
            b.finding.group_id.as_deref().unwrap_or(""),
            &b.finding.sink.file,
            b.finding.sink.line,
            &b.finding.sink.rule_id,
        );
        bucket_a
            .cmp(&bucket_b)
            .then(inferred_a.cmp(&inferred_b))
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
    // Key on (language, group_id, SINK SITE) — sink site = file + line +
    // rule_id. The sink site is what distinguishes genuinely separate
    // findings that happen to share a `group_id`: structurally identical
    // flows in different files hash to the same group tokens, so
    // group_id alone would wrongly collapse them into one row.
    //
    // Deliberately NOT keyed on `chain_display` or
    // `representative_flow_id`: the SAME logical finding can be reached
    // via more than one entry chain (e.g. dart's `handle_request → … →
    // execute` and `__module__ → handle_request → … → execute`) and
    // carry a different representative flow each time — same sink site,
    // same group_id, so it is one finding, not two duplicate rows.
    //
    // Source is omitted on purpose — co-tainted sources reaching the
    // same sink site fold into the primary's `additional_sources` (this
    // is "combine findings by source flow").
    if !group.is_empty() {
        format!(
            "{}\0{}\0{}\0{}\0{}",
            f.language, group, f.sink.file, f.sink.line, f.sink.rule_id
        )
    } else {
        // No group id to anchor on — fall back to the chain + flow id so
        // genuinely distinct flows don't collapse together.
        let chain = f.chain_display.join("\0");
        format!(
            "{}\0\0{}\0{}\0{}\0{}\0{}",
            f.language,
            chain,
            f.representative_flow_id.as_deref().unwrap_or(""),
            f.sink.file,
            f.sink.line,
            f.sink.rule_id
        )
    }
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

    let mut sources = Vec::with_capacity(1 + group.additional_sources.len());
    sources.push(group.finding.source.clone());
    sources.extend(group.additional_sources.iter().cloned());
    let primary_sink = group.finding.sink.clone();
    sources.sort_by(|a, b| {
        source_preference_rank_for_sink(a, Some(&primary_sink))
            .cmp(&source_preference_rank_for_sink(b, Some(&primary_sink)))
            .then_with(|| (a.file.as_str(), a.line, a.column).cmp(&(b.file.as_str(), b.line, b.column)))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    group.finding.source = sources[0].clone();
    // Distinct source sites can collapse onto the same conservative
    // field/container lineage. Prefer concrete rulepack sources over
    // inferred entry-point placeholders, then do not surface other
    // source sites unless they are aliases for the same exact call site.
    group.additional_sources = sources
        .into_iter()
        .skip(1)
        .filter(|source| same_source_location(&group.finding.source, source))
        .collect();

    let group_id = group
        .finding
        .group_id
        .clone()
        .unwrap_or_else(|| group.finding.representative_flow_id.clone().unwrap_or_default());
    let sink_token = all_sink_matches(group)
        .iter()
        .map(|sink| sink.rule_id.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join("+");
    let source_token = all_source_matches(group)
        .iter()
        .map(|source| source.rule_id.as_str())
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
    on_progress: &mut F,
) -> Vec<FindingWithChain>
where
    F: FnMut(AnalysisProgress),
{
    // ---- Phase 1: resolve rule matches to enclosing FuncIds ----
    let global = ws.db().global_index();
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
    if source_hits.is_empty() || sink_by_func.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    // Materialise per-source value-flow seeds in source order, using
    // transient value-flow graphs on cold misses. Broad scans can
    // touch thousands of source-bearing functions; keeping every full
    // `ValueFlowGraph` resident caused multi-GB RSS before the exact
    // source-seeded graph phase even started. Compute each transient
    // graph once per source-bearing function, derive all seeds in
    // that function, then drop it.
    struct SourceForFunction<'a> {
        index: usize,
        src: &'a RuleMatch,
    }
    let mut sources_by_func: AHashMap<FuncId, Vec<SourceForFunction<'_>>> = AHashMap::new();
    for (idx, src) in source_hits.iter().enumerate() {
        let Some(src_func_id) = func_id_for_match(ws, src) else {
            continue;
        };
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
        let value_flow =
            ws.value_flow()
                .graph_for_transient_with_caches(src_func_id, ws.db(), ws.inter_taint_caches());
        for source in sources {
            let seeds = source_seed_set(pack, source.src, src_decl, Some(value_flow.as_ref()));
            if seeds.is_empty() {
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
    let receiver_state_propagations = receiver_state_propagations_from_rulepack(pack);
    let idg = ws
        .db()
        .idg_service()
        .unwrap_or_else(|| ws.build_and_seed_idg_service());
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
        clean_output_overwrites: clean_output_overwrites_from_rulepack(pack),
        source_output_args: source_output_args_from_rulepack(pack),
        call_result_passthroughs: call_result_passthroughs_from_rulepack(pack),
        output_arg_flows: output_arg_flows_from_rulepack(pack),
        receiver_state_propagations,
        max_edge_precision: max_precision,
        ..Default::default()
    };
    let taint_caches = ws.inter_taint_caches();
    // Workspace-wide source-seeded graph index. The resident cache is
    // bounded and guarded by a rule/config fingerprint, so reuse
    // cannot keep stale graphs alive across rulepack or precision
    // changes and cannot grow without limit on large scans. Disk
    // persistence is opt-in for the same reason as source-analysis:
    // exact graphs are correct but can be very large.
    let workspace_taint_index = ws.taint_index();
    let taint_graph_fingerprint =
        taint_graph_config_fingerprint(pack, "taint-analysis", config.max_edge_precision);
    prepare_workspace_taint_graph_cache(ws, taint_graph_fingerprint);
    // AHashMap iteration order is hash-randomized per process. Sort
    // by FuncId.raw() so the per-source-group analysis order and
    // resulting finding fingerprints are stable across runs.
    let mut source_groups_sorted: Vec<(FuncId, &Vec<usize>)> =
        source_groups.iter().map(|(k, v)| (*k, v)).collect();
    source_groups_sorted.sort_by_key(|(k, _)| k.raw());
    let total_groups = source_groups_sorted.len();
    on_progress(AnalysisProgress::PhaseStarted {
        label: "building taint chains",
        total: total_groups as u64,
    });
    let debug_taint_phase = bonsai_diagnostics::debug::is_enabled("security-taint");
    let build_source_group = |&(src_func_id, indices): &(FuncId, &Vec<usize>)| {
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
            let anchor =
                if rule_match_kind_is_param(pack, &src.rule_id) || src.rule_id.starts_with("entry-point.") {
                    None
                } else {
                    Some(src.span)
                };
            let graph_key = (
                src_func_id,
                effective_source_seed_key(src_func_id, seeds, anchor, &output_arg_names, idg.as_ref()),
            );
            // Compute the per-`(source_func, seed_shape)` graph
            // exactly. The per-group cache removes duplicate work
            // inside this source function; the workspace cache gives
            // repeat SDK calls bounded reuse across invocations.
            let graph_started = debug_taint_phase.then(Instant::now);
            let graph = if let Some(hit) = group_graphs.get(&graph_key.1) {
                group_graph_hits = group_graph_hits.saturating_add(1);
                hit.clone()
            } else if let Some(hit) = workspace_taint_index.get(src_func_id, &graph_key.1) {
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
                    ws,
                    anchor,
                    &output_arg_names,
                ));
                let graph = workspace_taint_index.insert_if_absent(src_func_id, graph_key.1.clone(), graph);
                group_graphs.insert(graph_key.1.clone(), graph.clone());
                graph
            };
            if let Some(started) = graph_started {
                graph_nanos = graph_nanos.saturating_add(started.elapsed().as_nanos());
            }
            if graph.tainted_calls.is_empty() {
                empty_graphs = empty_graphs.saturating_add(1);
                continue;
            }
            tainted_calls_seen = tainted_calls_seen.saturating_add(graph.tainted_calls.len());
            let unresolved_call_index = GraphUnresolvedCallIndex::new(global.as_ref(), graph.as_ref());
            let attribution_started = debug_taint_phase.then(Instant::now);
            // Span set of every recorded tainted call on this
            // source graph — sanitizer credit pass uses it to
            // require data-flow connectivity rather than mere
            // chain co-occurrence.
            let tainted_call_spans: AHashSet<Span> =
                graph.tainted_calls.iter().map(|c| c.call_span).collect();
            let trace_index = trace_record_index(&graph.call_records);
            let canonical_chain_index = CanonicalChainIndex::new(&graph.call_records);
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
                let any_span_match = candidate_sinks
                    .iter()
                    .any(|snk| snk.language == src.language && spans_overlap(call.call_span, snk.span));
                for snk in candidate_sinks {
                    if snk.language != src.language {
                        continue;
                    }
                    if !source_can_precede_sink(pack, src, src_func_id, snk, call.caller) {
                        continue;
                    }
                    if any_span_match {
                        if !spans_overlap(call.call_span, snk.span) {
                            continue;
                        }
                    } else if !tainted_call_matches_sink(call, snk) {
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
                        continue;
                    }
                    let Some(sink_rule) = pack.find_rule_by_id(&snk.rule_id) else {
                        continue;
                    };
                    if prototype_pollution_sink_is_guarded(ws, sink_rule, snk) {
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
                        ) {
                            continue;
                        }
                    }
                    if !emitted_for_source_sink_flow.insert(source_sink_flow_emission_key(idx, snk, call)) {
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
                            chain_funcs: &evidence.chain_funcs,
                            chain_names: evidence.chain_names.clone(),
                            san_by_func: &san_by_func,
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
    let parallel_groups: Vec<Vec<FindingWithChain>> = if worker_count > 1 && source_groups_sorted.len() > 1 {
        match rayon::ThreadPoolBuilder::new().num_threads(worker_count).build() {
            Ok(pool) => pool.install(|| source_groups_sorted.par_iter().map(build_source_group).collect()),
            Err(_) => source_groups_sorted.iter().map(build_source_group).collect(),
        }
    } else {
        source_groups_sorted.iter().map(build_source_group).collect()
    };
    let parallel_out: Vec<FindingWithChain> = parallel_groups.into_iter().flatten().collect();
    out.extend(parallel_out);
    // Progress callback isn't `Send`, so the parallel pass can't tick
    // mid-flight. Replay one tick per group now so consumers see the
    // bar advance to the declared total before the phase finishes.
    for _ in 0..total_groups {
        on_progress(AnalysisProgress::PhaseTicked);
    }
    on_progress(AnalysisProgress::PhaseFinished);
    finish_workspace_taint_graph_cache(ws);
    out
}

/// Build a deterministic key for a seed token set so the same seeds
/// hash to the same `exact_graphs` cache slot regardless of insertion
/// order. AHashSet iteration is randomised per process, which would
/// otherwise miss obvious cache hits.
fn taint_graph_config_fingerprint(
    pack: &Rulepack,
    mode: &'static str,
    max_precision: Option<Precision>,
) -> u64 {
    let rule_content_fingerprint = *pack.taint_graph_rule_content_fingerprint.get_or_init(|| {
        let mut rule_tokens = Vec::new();
        let mut rules = pack.all_rules();
        rules.sort_by(|a, b| {
            a.language
                .cmp(&b.language)
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.id.cmp(&b.id))
        });
        for rule in rules.into_iter().filter(|rule| rule.enabled) {
            rule_tokens.push(format!(
                "rule:{}:{}:{}",
                rule.language,
                rule_kind_token(rule.kind),
                rule.id
            ));
            rule_tokens
                .push(serde_json::to_string(rule).unwrap_or_else(|_| format!("rule-json-error:{}", rule.id)));
        }
        bonsai_hash::fnv1a_names64(&rule_tokens)
    });
    let tokens = vec![
        "taint-graph-config-v2".to_string(),
        format!("mode={mode}"),
        format!(
            "max_precision={}",
            max_precision.map(precision_label).unwrap_or("all")
        ),
        format!("rule_content={rule_content_fingerprint}"),
    ];
    bonsai_hash::fnv1a_names64(&tokens)
}

fn prepare_workspace_taint_graph_cache(ws: &Workspace, config_fingerprint: u64) {
    let index = ws.taint_index();
    index.clear_for_config(config_fingerprint);
    let Some(root) = ws.db().workspace_root() else {
        return;
    };
    let sidecar = bonsai_workspace::taint_index::TaintGraphIndex::sidecar_path(&root);
    if let Err(err) = bonsai_workspace::taint_index::cleanup_sidecar_temp_files(&sidecar) {
        tracing::warn!(
            path = %sidecar.display(),
            error = %err,
            "taint graph factstore temp cleanup failed"
        );
    }
    if let Err(err) = index.load_from_disk_for_config(&sidecar, ws.db(), config_fingerprint) {
        tracing::warn!(
            path = %sidecar.display(),
            error = %err,
            "taint graph factstore load failed"
        );
    }
    if !taint_graph_persistence_enabled() {
        return;
    }
    if let Err(err) = index.begin_persist_to_disk(&sidecar, ws.db(), config_fingerprint) {
        tracing::warn!(
            path = %sidecar.display(),
            error = %err,
            "taint graph factstore write-through setup failed"
        );
    }
}

fn taint_graph_persistence_enabled() -> bool {
    std::env::var("BONSAI_TAINT_GRAPH_PERSIST")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
}

fn finish_workspace_taint_graph_cache(ws: &Workspace) {
    if let Err(err) = ws.taint_index().finish_persist_to_disk(ws.db()) {
        tracing::warn!(error = %err, "taint graph factstore finish failed");
    }
}

fn rule_kind_token(kind: RuleKind) -> &'static str {
    match kind {
        RuleKind::Source => "source",
        RuleKind::Sink => "sink",
        RuleKind::Sanitizer => "sanitizer",
    }
}

fn sorted_seed_key(seeds: &TokenSet) -> Vec<String> {
    let mut sorted: Vec<String> = seeds.iter().cloned().collect();
    sorted.sort();
    sorted
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
        .unwrap_or_else(|| available.clamp(1, 2));
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
    idg: &bonsai_idg::IdgQueryService,
) -> Vec<String> {
    if let Some(span) = anchor {
        let mut seed_nodes = Vec::new();
        if !output_arg_names.is_empty() {
            for arg_name in output_arg_names {
                if arg_name.is_empty() {
                    continue;
                }
                seed_nodes.extend(idg.nodes_for_name_after_span(source_func, arg_name, span));
            }
        }
        if seed_nodes.is_empty() {
            seed_nodes = idg.source_seed_nodes_at_span(source_func, span);
        }
        if !seed_nodes.is_empty() {
            seed_nodes.sort();
            seed_nodes.dedup();
            let node_ids = seed_nodes
                .iter()
                .map(|node| node.0.to_string())
                .collect::<Vec<_>>()
                .join(",");
            return vec![format!("__idg_seed_nodes@{node_ids}")];
        }
    }
    sorted_seed_key_with_anchor(seeds, anchor, output_arg_names)
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
    ws: &Workspace,
    source_anchor: Option<bonsai_common::Span>,
    output_arg_names: &[String],
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
    let idg = db
        .idg_service()
        .unwrap_or_else(|| ws.build_and_seed_idg_service());
    bonsai_taint::entry_taint_graph_from_idg_with_max_precision(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        &config.receiver_state_propagations,
        &config.call_result_passthroughs,
        &config.output_arg_flows,
        config.max_edge_precision,
        db,
        idg.as_ref(),
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
) -> EntryTaintGraph {
    let idg = db
        .idg_service()
        .unwrap_or_else(|| ws.build_and_seed_idg_service());
    bonsai_taint::entry_taint_call_records_from_idg_with_max_precision(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        &config.receiver_state_propagations,
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
    src.line < snk.line || (src.line == snk.line && src.column <= snk.column)
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
    // Carrier = base identifier of the source expression (`Input`,
    // `req` for `req.query`). Without a carrier we cannot prove the
    // tainted value is the one wrapped, so fail closed (no credit).
    let Some(carrier) = source_expr_base_identifier(&src.match_text) else {
        return false;
    };
    sink_tainted_args
        .iter()
        .any(|arg| sanitizer_call_wraps_carrier(&arg.value_text, text, carrier))
}

/// True when `value_text` invokes `callee` as a CALL (anchored on the
/// `callee(` form, and `callee` not preceded by an identifier char so a
/// longer identifier such as `myEscapeHtml` never matches) and that
/// call's balanced argument list mentions `carrier` as a whole token.
fn sanitizer_call_wraps_carrier(value_text: &str, callee: &str, carrier: &str) -> bool {
    if callee.is_empty() {
        return false;
    }
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
        while idx < bytes.len() && bytes[idx] == b' ' {
            idx += 1;
        }
        if idx >= bytes.len() || bytes[idx] != b'(' {
            continue;
        }
        if let Some(args) = balanced_paren_slice(value_text, idx) {
            if text_mentions_token(args, carrier) {
                return true;
            }
        }
    }
    false
}

/// Slice between the `(` at `open_idx` and its matching `)`, tracking
/// nesting. `None` when the parens are unbalanced.
fn balanced_paren_slice(text: &str, open_idx: usize) -> Option<&str> {
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
                    return Some(&text[open_idx + 1..idx]);
                }
            }
            _ => {}
        }
        idx += 1;
    }
    None
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
) -> bool {
    if sanitizer_func == source_func && !match_precedes_or_same(src, san) && !dataflow_connected {
        return false;
    }
    if sanitizer_func == sink_func
        && !match_precedes_or_same(san, snk)
        && !sanitizer_is_nested_in_tainted_sink_arg(src, san, sink_tainted_args)
    {
        return false;
    }
    true
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

    key_vars
        .iter()
        .any(|key| prototype_key_denylist_guard_present(&compact, key))
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

/// Resolve the source rule's `source_output_args` indices to the
/// concrete carrier names at the source's call site. The IDG seeder
/// then includes post-call reads/writes of those carriers so the
/// side-effect taint flows into downstream consumers.
fn output_arg_names_for_match(pack: &Rulepack, src: &RuleMatch, decl: &bonsai_lang_api::Decl) -> Vec<String> {
    use bonsai_lang_api::FlowEvent;
    let Some(rule) = pack.find_rule_by_id(&src.rule_id) else {
        return Vec::new();
    };
    let Some(semantics) = rule.taint_semantics.as_ref() else {
        return Vec::new();
    };
    if semantics.source_output_args.is_empty() {
        return Vec::new();
    }
    fn find_call<'a>(events: &'a [FlowEvent], target: bonsai_common::Span) -> Option<&'a FlowEvent> {
        for event in events {
            match event {
                FlowEvent::Call { span, .. } if *span == target => return Some(event),
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    if let Some(v) = find_call(then_events, target) {
                        return Some(v);
                    }
                    if let Some(v) = find_call(else_events, target) {
                        return Some(v);
                    }
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    if let Some(v) = find_call(body, target) {
                        return Some(v);
                    }
                    if let Some(v) = find_call(catch_events, target) {
                        return Some(v);
                    }
                    if let Some(v) = find_call(finally_events, target) {
                        return Some(v);
                    }
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => {
                    if let Some(v) = find_call(body, target) {
                        return Some(v);
                    }
                }
                _ => {}
            }
        }
        None
    }
    let Some(FlowEvent::Call { args, .. }) = find_call(&decl.flow_events, src.span) else {
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
    if let Some(graph) = value_flow {
        seed_source_nodes_from_value_flow(src, graph, &mut out);
    }
    if is_inferred || is_param_rule {
        insert_taint_aliases(&mut out, &src.match_text);
        insert_descendant_taint_aliases(&mut out, &src.match_text);
    }
    collect_source_seed_targets(&decl.flow_events, src, source_output_args, &mut out);
    if out.is_empty() {
        insert_taint_aliases(&mut out, &src.match_text);
    }
    out
}

fn seed_source_nodes_from_value_flow(src: &RuleMatch, graph: &ValueFlowGraph, out: &mut TokenSet) {
    for node in value_flow_match::rule_match_to_nodes(src, graph) {
        let text = node.value_text.trim();
        if text.is_empty() || source_seed_text_is_literal(text) {
            continue;
        }
        insert_taint_aliases(out, text);
        insert_descendant_taint_aliases(out, text);
    }
}

fn collect_source_seed_targets(
    events: &[bonsai_lang_api::FlowEvent],
    src: &RuleMatch,
    source_output_args: &[usize],
    out: &mut TokenSet,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call,
                source_names,
                source_call_args,
                ..
            } => {
                let source_text_matches = source_name
                    .as_deref()
                    .is_some_and(|n| security_text_matches_source_strict(n, &src.match_text))
                    || source_call
                        .as_deref()
                        .is_some_and(|n| security_text_matches_source_strict(n, &src.match_text))
                    || source_names
                        .iter()
                        .any(|n| security_text_matches_source_strict(n, &src.match_text))
                    || source_call_args
                        .iter()
                        .any(|n| security_text_matches_source_strict(n, &src.match_text));
                if span_contains(*span, src.span) || spans_overlap(*span, src.span) || source_text_matches {
                    if !source_output_args.is_empty() {
                        seed_source_output_text_args(out, source_call_args, source_output_args);
                        continue;
                    }
                    if !target.is_empty() {
                        insert_taint_aliases(out, target);
                    }
                    let _ = source_call;
                    if let Some(source_name) = source_name.as_deref() {
                        if security_text_matches_source_strict(source_name, &src.match_text) {
                            insert_taint_aliases(out, source_name);
                        }
                    }
                    seed_descendant_aliases_for_qualified_source_reads(out, source_names, &src.match_text);
                    // Tighter match here than `security_text_matches_source`:
                    // when the source rule matches a qualified callee
                    // like `os.getenv`, the assignment's `source_names`
                    // includes both the tail (`getenv`) and the
                    // receiver (`os`). The receiver IS NOT a source
                    // term — adding it taints every `os.<other>` call
                    // in the same function (Task #279). Only seed
                    // entries that are equal to the source text or a
                    // proper qualified-tail of it.
                    for name in source_names {
                        if security_text_matches_source_strict(name, &src.match_text) {
                            insert_taint_aliases(out, name);
                        }
                    }
                    for name in source_call_args {
                        if security_text_matches_source_strict(name, &src.match_text) {
                            insert_taint_aliases(out, name);
                        }
                    }
                    if target_is_destructuring_pattern(target) {
                        for name in source_names {
                            insert_taint_aliases(out, name);
                        }
                    }
                }
            }
            FlowEvent::Call {
                span,
                name,
                receiver,
                args,
                ..
            } => {
                // Receiver-only match (e.g. receiver `os` matching source
                // text `os.getenv` via substring containment) was over-
                // broad: any call whose receiver was the same module
                // got its arg places seeded as if the call itself were
                // the source. That conflated `os.execute(CONST_OK)`
                // with the source seed of `os.getenv(...)` in the same
                // function — a Lua intra-fn precision regression
                // (Task #279). Match name OR span overlap only; the
                // receiver alone isn't enough to identify the source
                // site.
                let call_matches = span_contains(*span, src.span)
                    || spans_overlap(*span, src.span)
                    || security_text_matches_source_strict(name, &src.match_text);
                let _ = receiver;
                if call_matches {
                    if !source_output_args.is_empty() {
                        seed_source_output_call_args(out, args, source_output_args);
                        continue;
                    }
                    for arg in args {
                        if let Some(place) = arg.place.as_deref() {
                            insert_taint_aliases(out, place);
                            if source_arg_is_mutable_output(&arg.value_text) {
                                insert_descendant_taint_aliases(out, place);
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
                collect_source_seed_targets(then_events, src, source_output_args, out);
                collect_source_seed_targets(else_events, src, source_output_args, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_source_seed_targets(body, src, source_output_args, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_source_seed_targets(body, src, source_output_args, out);
                collect_source_seed_targets(catch_events, src, source_output_args, out);
                collect_source_seed_targets(finally_events, src, source_output_args, out);
            }
            _ => {}
        }
    }
}

fn seed_source_output_text_args(out: &mut TokenSet, args: &[String], source_output_args: &[usize]) {
    for &index in source_output_args {
        let Some(text) = args.get(index).map(|value| value.trim()) else {
            continue;
        };
        if text.is_empty() || source_seed_text_is_literal(text) {
            continue;
        }
        insert_taint_aliases(out, text);
        insert_descendant_taint_aliases(out, text);
    }
}

fn seed_source_output_call_args(
    out: &mut TokenSet,
    args: &[bonsai_lang_api::CallArg],
    source_output_args: &[usize],
) {
    for &index in source_output_args {
        let Some(arg) = args.get(index) else {
            continue;
        };
        let text = arg.place.as_deref().unwrap_or(arg.value_text.as_str()).trim();
        if text.is_empty() || source_seed_text_is_literal(text) {
            continue;
        }
        insert_taint_aliases(out, text);
        insert_descendant_taint_aliases(out, text);
    }
}

fn source_seed_text_is_literal(text: &str) -> bool {
    let text = text.trim();
    if text.len() < 2 {
        return false;
    }
    let Some(first) = text.chars().next() else {
        return false;
    };
    let Some(last) = text.chars().last() else {
        return false;
    };
    matches!(first, '"' | '\'' | '`') && first == last
}

fn seed_descendant_aliases_for_qualified_source_reads(
    out: &mut TokenSet,
    source_names: &[String],
    source_text: &str,
) {
    for name in source_names {
        let normalised = security_normalise_qualified_text(name);
        let Some((base, _)) = normalised.split_once('.') else {
            continue;
        };
        if source_base_matches(base, source_text) {
            insert_descendant_taint_aliases(out, base);
            insert_descendant_taint_aliases(out, source_text);
        }
    }
}

fn source_base_matches(base: &str, source_text: &str) -> bool {
    security_text_matches_source_strict(base, source_text)
        || security_text_matches_source_strict(
            strip_security_sigils(base),
            strip_security_sigils(source_text),
        )
}

fn strip_security_sigils(text: &str) -> &str {
    text.trim().trim_start_matches(&['$', '@', '%'][..])
}

fn source_arg_is_mutable_output(text: &str) -> bool {
    let text = text.trim();
    text.starts_with("&mut ")
        || text.starts_with("out ")
        || text.starts_with("ref ")
        || text.contains(" out ")
        || text.contains(" ref ")
}

fn target_is_destructuring_pattern(target: &str) -> bool {
    let target = target.trim();
    target.contains(',')
        || target.starts_with('[')
        || target.starts_with('(')
        || target.starts_with('{')
        || target.contains(":=")
}

fn insert_taint_aliases(out: &mut TokenSet, text: &str) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }
    out.insert(trimmed.to_string());
    let normalised = security_normalise_qualified_text(trimmed);
    if normalised != trimmed {
        out.insert(normalised);
    }
}

fn insert_descendant_taint_aliases(out: &mut TokenSet, text: &str) {
    let mut aliases = TokenSet::default();
    insert_taint_aliases(&mut aliases, text);
    for alias in aliases {
        if alias.is_empty() || alias.contains('*') {
            continue;
        }
        out.insert(alias.clone());
        out.insert(format!("{alias}.*"));
    }
}

/// Source seeding uses strict identity only. Receiver substring
/// matching (`os` as a match for `os.getenv`) taints every sibling
/// member on the same object/module, so source expansion is limited
/// to equality, normalized equality, or exact qualified-tail equality.
fn security_text_matches_source_strict(text: &str, source_text: &str) -> bool {
    let text = text.trim();
    let source_text = source_text.trim();
    if text.is_empty() || source_text.is_empty() {
        return false;
    }
    if text == source_text {
        return true;
    }
    let text_norm = security_normalise_qualified_text(text);
    let src_norm = security_normalise_qualified_text(source_text);
    if text_norm == src_norm {
        return true;
    }
    // Tail match: `getenv` matches `os.getenv` (one is a suffix of
    // the other when split on `.` / `:`). Equivalent to: the bare
    // tails are equal.
    let text_tail = text.rsplit(&['.', ':'][..]).next().unwrap_or(text);
    let src_tail = source_text.rsplit(&['.', ':'][..]).next().unwrap_or(source_text);
    text_tail == src_tail && !text_tail.is_empty()
}

fn security_normalise_qualified_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_brackets = false;
    let mut chars = text.trim().chars().peekable();
    while matches!(chars.peek(), Some('&' | '*')) {
        chars.next();
    }
    while let Some(c) = chars.next() {
        match c {
            '-' if matches!(chars.peek(), Some('>')) => {
                chars.next();
                out.push('.');
            }
            '[' => {
                in_brackets = true;
                out.push('.');
            }
            ']' => in_brackets = false,
            '\'' | '"' if in_brackets => {}
            _ => out.push(c),
        }
    }
    out.trim_matches('.').to_string()
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

fn build_pattern_only_findings(
    ws: &Workspace,
    sinks: &[RuleMatch],
    pack: &Rulepack,
    taint_sink_sites: &AHashSet<(String, String, u32, u32)>,
) -> Vec<FindingWithChain> {
    let mut emitted: AHashSet<(String, String, u32, u32)> = AHashSet::new();
    let mut out = Vec::new();
    for snk in sinks {
        let site_key = (snk.rule_id.clone(), snk.file.clone(), snk.line, snk.column);
        if taint_sink_sites.contains(&site_key) || !emitted.insert(site_key) {
            continue;
        }
        let chain_funcs: Vec<FuncId> = func_id_for_match(ws, snk).into_iter().collect();
        if let Some(finding) = make_pattern_finding(snk, pack, &chain_funcs) {
            out.push(FindingWithChain { finding, chain_funcs });
        }
    }
    out
}

fn make_pattern_finding(snk: &RuleMatch, pack: &Rulepack, _chain_funcs: &[FuncId]) -> Option<Finding> {
    let sink_rule = pack.find_rule_by_id(&snk.rule_id)?;
    let group_tokens = [
        snk.rule_id.clone(),
        snk.file.clone(),
        snk.line.to_string(),
        snk.column.to_string(),
    ];
    let group_id = format!("G:{:016x}", bonsai_hash::fnv1a_names64(&group_tokens));
    let flow_id = bonsai_inspect::compute_flow_id(&group_tokens);
    let source_rule_id = format!("pattern:{}", sink_rule.id);
    let finding_id = compute_finding_id(&source_rule_id, &sink_rule.id, &group_id, &snk.language);
    let source = FindingMatch {
        rule_id: source_rule_id,
        file: snk.file.clone(),
        line: snk.line,
        column: snk.column,
        text: snk.match_text.clone(),
        enclosing_fn: snk.enclosing_fn.clone(),
        tag: Some("pattern".to_string()),
        severity: None,
        category: Some("pattern".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: Vec::new(),
    };
    let sink = FindingMatch::from_rule_match(snk, sink_rule);
    let chain_display = snk
        .enclosing_fn
        .as_ref()
        .map(|name| vec![name.clone()])
        .unwrap_or_default();
    // Pattern-only findings are exact local rule matches, not taint/source
    // reachability claims. They carry no propagation path to complete.
    Some(Finding {
        finding_id,
        language: snk.language.clone(),
        source,
        sink,
        sanitizers_seen: Vec::new(),
        group_id: Some(group_id.clone()),
        representative_flow_id: Some(flow_id),
        analysis_complete: true,
        analysis_incomplete_reasons: Vec::new(),
        chain_display,
        taint_path: Vec::new(),
        hops: Vec::new(),
        tag: sink_rule.tag.clone(),
        severity: sink_rule.severity,
        precision: precision_label(Precision::Exact).to_string(),
        cwe: sink_rule.cwe.clone(),
        owasp: sink_rule.owasp.clone(),
        status: FindingStatus::Unsanitized,
        from_test: crate::finding::path_is_test_file(&snk.file),
    })
}

fn rule_is_pattern_only_finding(rule: &Rule) -> bool {
    rule.kind == RuleKind::Sink
        && rule.enabled
        && !rule_has_taint_predicate(rule)
        && (rule.category.as_deref() == Some("source-independent")
            || rule.match_spec.kind == MatchKind::Missing)
}

fn rule_is_non_taint_sink(rule: &Rule) -> bool {
    rule_is_pattern_only_finding(rule)
        || (rule.kind == RuleKind::Sink
            && rule.enabled
            && !rule_has_taint_predicate(rule)
            && rule.category.as_deref() == Some("lifecycle-audit"))
}

fn rule_has_taint_predicate(rule: &Rule) -> bool {
    rule.constraints.0.iter().any(|constraint| {
        matches!(
            constraint,
            ConstraintKind::ArgTainted { .. }
                | ConstraintKind::AnyArgTainted { .. }
                | ConstraintKind::ReceiverTainted { .. }
        )
    })
}

struct FindingBuildContext<'a> {
    group_id: Option<String>,
    flow_id: Option<String>,
    source_func: FuncId,
    sink_func: FuncId,
    chain_funcs: &'a [FuncId],
    chain_names: Vec<String>,
    san_by_func: &'a AHashMap<FuncId, Vec<&'a RuleMatch>>,
    /// Spans of every call site the engine recorded as carrying
    /// tainted argument flow on this source's graph. A sanitizer
    /// only credits the finding when its match span overlaps one
    /// of these — without this filter, any function that happens
    /// to live on the call path (a `pthread_mutex_lock` somewhere,
    /// a `path_prefix_strncmp` on an unrelated branch) would be
    /// credited as a "sanitizer seen" purely because it shares the
    /// chain with the tainted flow. Sanitizer credit must be
    /// data-flow-aware, not call-graph-aware.
    tainted_call_spans: &'a AHashSet<Span>,
    sink_tainted_args: Vec<TaintedArgInfo>,
    taint_path: Vec<TaintPropagationStep>,
    precision: Precision,
    analysis_incomplete_reasons: Vec<String>,
}

fn make_finding(
    src: &RuleMatch,
    snk: &RuleMatch,
    pack: &Rulepack,
    context: FindingBuildContext<'_>,
) -> Option<Finding> {
    let skr = pack.find_rule_by_id(&snk.rule_id)?;
    let is_inferred = src.rule_id.starts_with("entry-point.");
    let src_match = if is_inferred {
        FindingMatch::from_inferred(src)
    } else {
        let sr = pack.find_rule_by_id(&src.rule_id)?;
        FindingMatch::from_rule_match(src, sr)
    };
    let src_rule_id_for_id = if is_inferred {
        src.rule_id.as_str()
    } else {
        &src_match.rule_id
    };
    let group = context.group_id.unwrap_or_else(|| {
        let tokens = [src.file.clone(), snk.file.clone()];
        format!("G:{:016x}", bonsai_hash::fnv1a_names64(&tokens))
    });
    let finding_id = compute_finding_id(src_rule_id_for_id, &skr.id, &group, &src.language);

    let mut sanitizers_seen: Vec<FindingMatch> = Vec::new();
    let mut seen_keys: AHashSet<(String, u32, u32)> = AHashSet::new();
    // Walk the actual `FuncId`s on this chain (not their names) so
    // sanitizers in unrelated same-named functions can't cross-
    // bridge. Combined with the data-flow tainted-call-span gate
    // below, this keeps credit semantically precise.
    for &hop_func in context.chain_funcs {
        let Some(sanitizer_hits) = context.san_by_func.get(&hop_func) else {
            continue;
        };
        for sanitizer_match in sanitizer_hits {
            let dataflow_connected =
                sanitizer_call_overlaps_tainted_call(sanitizer_match, context.tainted_call_spans)
                    || sanitizer_is_nested_in_tainted_sink_arg(src, sanitizer_match, &context.sink_tainted_args);
            if !sanitizer_can_attach(
                src,
                context.source_func,
                sanitizer_match,
                hop_func,
                snk,
                context.sink_func,
                &context.sink_tainted_args,
                dataflow_connected,
            ) {
                continue;
            }
            // Data-flow-aware credit: the sanitizer's call site must
            // itself be a tainted call on this graph. Without this
            // gate any rule firing somewhere on the chain credits the
            // finding even when its argument has nothing to do with
            // the source's tainted value.
            if !dataflow_connected {
                continue;
            }
            let dedup_key = (
                sanitizer_match.file.clone(),
                sanitizer_match.line,
                sanitizer_match.column,
            );
            if seen_keys.insert(dedup_key) {
                if let Some(rule) = pack.find_rule_by_id(&sanitizer_match.rule_id) {
                    sanitizers_seen.push(FindingMatch::from_rule_match(sanitizer_match, rule));
                }
            }
        }
    }

    let status = compute_status(&sanitizers_seen, skr.tag.as_deref());

    let mut sink_match = FindingMatch::from_rule_match(snk, skr);
    sink_match.tainted_args = context.sink_tainted_args;

    // Tag the finding when EITHER endpoint lives in a conventional
    // test path. The CLI / SDK consumer can use `--exclude-tests`
    // to drop these for "production review" reports without
    // rebuilding the analysis.
    let from_test = crate::finding::path_is_test_file(&src.file)
        || crate::finding::path_is_test_file(&snk.file)
        || context
            .taint_path
            .iter()
            .any(|step| crate::finding::path_is_test_file(&step.file));

    // Trust-aware severity. Source rules carry a `trust` tag
    // (`remote`, `local`, `inferred`). Local-trust sources are
    // CLI args / env vars / files the local user controls — real
    // attack surface for setuid binaries, but lower priority than
    // network-derived flows in a typical web app review. Demote
    // the rule's declared sink severity by one tier when the
    // source is local-trust so the `severity: high` filter retains
    // signal for genuinely high-priority (network-derived) flows.
    let severity = match (skr.severity, src_match.trust.as_deref()) {
        (Some(sev), Some("local" | "inferred")) => Some(demote_severity_one_tier(sev)),
        (sev, _) => sev,
    };

    Some(Finding {
        finding_id,
        language: src.language.clone(),
        source: src_match,
        sink: sink_match,
        sanitizers_seen,
        group_id: Some(group),
        representative_flow_id: context.flow_id,
        analysis_complete: context.analysis_incomplete_reasons.is_empty(),
        analysis_incomplete_reasons: context.analysis_incomplete_reasons,
        chain_display: context.chain_names,
        taint_path: context.taint_path,
        hops: Vec::new(),
        tag: skr.tag.clone(),
        severity,
        precision: precision_label(context.precision).to_string(),
        cwe: skr.cwe.clone(),
        owasp: skr.owasp.clone(),
        status,
        from_test,
    })
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
    precision_from_label(label).is_some_and(|precision| precision <= max_precision)
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

fn clean_output_overwrites_from_rulepack(pack: &Rulepack) -> Vec<CleanOutputOverwrite> {
    pack.all_rules()
        .into_iter()
        .filter(|rule| rule.enabled && rule.kind == RuleKind::Sanitizer)
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
        .collect()
}

fn clean_output_overwrites_from_rulepack_for_languages(
    pack: &Rulepack,
    languages: &AHashSet<String>,
) -> Vec<CleanOutputOverwrite> {
    pack.all_rules()
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
        .collect()
}

fn idg_transfer_options_from_rulepack_shapes(
    overwrites: &[CleanOutputOverwrite],
    source_outputs: &[SourceOutputArgs],
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

pub fn seed_idg_service_for_rulepack(ws: &Workspace, pack: &Rulepack) {
    let languages = workspace_languages(ws);
    let overwrites = clean_output_overwrites_from_rulepack_for_languages(pack, &languages);
    let source_outputs = source_output_args_from_rulepack_for_languages(pack, &languages);
    let options = idg_transfer_options_from_rulepack_shapes(&overwrites, &source_outputs);
    let _ = ws.build_and_seed_idg_service_with_transfer_options(&options);
}

fn source_output_args_from_rulepack(pack: &Rulepack) -> Vec<SourceOutputArgs> {
    pack.all_rules()
        .into_iter()
        .filter(|rule| rule.enabled && rule.kind == RuleKind::Source)
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
            Some(SourceOutputArgs {
                callee,
                output_arg_indices: semantics.source_output_args.clone(),
            })
        })
        .collect()
}

fn source_output_args_from_rulepack_for_languages(
    pack: &Rulepack,
    languages: &AHashSet<String>,
) -> Vec<SourceOutputArgs> {
    pack.all_rules()
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
            Some(SourceOutputArgs {
                callee,
                output_arg_indices: semantics.source_output_args.clone(),
            })
        })
        .collect()
}

fn call_result_passthroughs_from_rulepack(pack: &Rulepack) -> Vec<CallResultPassthrough> {
    pack.all_rules()
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
            Some(CallResultPassthrough {
                callee,
                input_arg_indices: semantics.call_result_passthrough_args.clone(),
                input_receiver: semantics.call_result_passthrough_receiver,
            })
        })
        .collect()
}

fn output_arg_flows_from_rulepack(pack: &Rulepack) -> Vec<OutputArgFlow> {
    pack.all_rules()
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
                            value_arg_indices: flow.value_arg_indices.clone(),
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .collect()
}

fn semantic_transfer_callee(target: &RuleTarget) -> Option<String> {
    target
        .name
        .clone()
        .or_else(|| target.attribute.as_ref().map(|parts| parts.join(".")))
        .or_else(|| target.regex.as_ref().map(|regex| format!("regex:{regex}")))
}

fn receiver_state_propagations_from_rulepack(pack: &Rulepack) -> Vec<ReceiverStatePropagation> {
    pack.all_rules()
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
        .collect()
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
