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
use crate::rule::{ConstraintKind, MatchKind, Rule, RuleKind, Severity};
use crate::sanitizer_credit::{sanitizer_credits_sink_tag, sanitizer_tag_is_recognized_non_crediting};
use ahash::{AHashMap, AHashSet};
use anyhow::Result;
use bonsai_common::{FuncId, Precision, Span, SymbolId};
use bonsai_lang_api::LanguageRegistry;
use bonsai_taint::{
    CleanOutputOverwrite, EntryTaintGraph, InterTaintCaches, InterTaintConfig, ReceiverStatePropagation,
    SourceOutputArgs, TaintedCall, TaintedCallEdge, TaintedCallKind, TokenSet, ValueFlowGraph,
};
use bonsai_workspace::Workspace;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

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

#[derive(Clone, Debug, Default)]
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
    /// Optional maximum tolerated flow precision. Lower enum values are
    /// more precise, so `Some(Precision::Narrowed)` keeps exact and
    /// narrowed findings while dropping over-approximate/unknown ones.
    pub max_precision: Option<Precision>,
    /// When true, drop findings whose source OR sink lives in a
    /// conventional test path (`test/`, `tests/`, `*_test.go`, etc.).
    /// See `crate::finding::path_is_test_file` for the exact rule.
    pub exclude_tests: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SourceAnalysisOptions {
    pub source: Option<String>,
    pub trust: Option<String>,
    pub category: Option<String>,
    pub tag: Option<String>,
    pub files: Vec<String>,
    pub exclude_files: Vec<String>,
    /// See `TaintAnalysisOptions::include_inferred_sources`.
    pub include_inferred_sources: bool,
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
}

#[derive(Clone, Debug)]
pub struct CombinedSourceAnalysisCandidate {
    pub source: FindingMatch,
    pub chain_names: Vec<String>,
    pub path: Vec<FuncId>,
    pub flow_id: String,
    pub taint_path: Vec<TaintPropagationStep>,
    pub additional_sources: Vec<FindingMatch>,
}

#[derive(Clone, Debug)]
pub struct SourceAnalysisReport {
    pub candidates: Vec<CombinedSourceAnalysisCandidate>,
    pub source_rule_count: usize,
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
        source_hits.extend(infer_entry_point_sources(ws));
    }
    filter_source_hits_by_metadata(
        &mut source_hits,
        pack,
        options.trust.as_deref(),
        options.category.as_deref(),
        None,
    );
    filter_by_path(&mut source_hits, &options.files, &options.exclude_files);

    let pattern_sinks: Vec<&Rule> = sinks
        .iter()
        .copied()
        .filter(|rule| rule_is_pattern_only_finding(rule))
        .collect();
    let source_languages: AHashSet<&str> = source_hits.iter().map(|hit| hit.language.as_str()).collect();
    sinks.retain(|rule| source_languages.contains(rule.language.as_str()));
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

    let mut findings_raw = build_findings_chain_aware(
        ws,
        &source_hits,
        &sink_hits,
        &sanitizer_hits,
        pack,
        options.interprocedural_budget,
        options.intra_worklist_cap,
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
        af.source.rule_id.cmp(&bf.source.rule_id)
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
    if options.exclude_tests {
        // Test-path post-filter — catches cross-file flows where one
        // side wasn't pruned earlier (e.g. prod source → test sink).
        findings.retain(|combined| !combined.finding.from_test);
    }
    // Sort highest-severity-first, then by finding id so two runs
    // produce identical output ordering.
    findings.sort_by(|a, b| {
        b.finding
            .severity
            .cmp(&a.finding.severity)
            .then_with(|| a.finding.finding_id.cmp(&b.finding.finding_id))
    });

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
        source_hits.extend(infer_entry_point_sources(ws));
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
    sort_matches(&mut source_hits);

    let global = ws.db().global_index();
    let func_ids = function_ids_by_lang_file_name(ws);
    let source_graph_config = InterTaintConfig {
        sanitizers: TokenSet::default(),
        budget: InterTaintConfig::default().budget,
        intra_worklist_cap: None,
        source_bearing_functions: AHashSet::default(),
        clean_output_overwrites: clean_output_overwrites_from_rulepack(pack),
        source_output_args: source_output_args_from_rulepack(pack),
        receiver_state_propagations: receiver_state_propagations_from_rulepack(pack),
        ..Default::default()
    };
    let source_graph_caches = ws.inter_taint_caches();
    on_progress(AnalysisProgress::PhaseStarted {
        label: "enumerating source paths",
        total: source_hits.len() as u64,
    });
    // Workspace-wide taint-graph index (Stage 6). Lifted out of the
    // per-invocation map so re-running source-analysis with a
    // different `--tag` filter against the same workspace +
    // rulepack reuses cached graphs. Per-invocation
    // `local_graphs` map kept as L1 to avoid re-cloning Arcs from
    // the workspace cache for in-pass duplicates.
    let workspace_taint_index = ws.taint_index();
    let local_graphs: parking_lot::RwLock<
        AHashMap<(FuncId, Vec<String>), Arc<EntryTaintGraph>>,
    > = parking_lot::RwLock::new(AHashMap::new());
    use rayon::prelude::*;
    // Per-thread `seen` Vecs merged at the end so the parallel
    // collect doesn't serialise on a global set lock; the second
    // `seen` pass below is a single-threaded canonicalisation.
    let parallel_candidates: Vec<SourceAnalysisCandidate> = source_hits
        .par_iter()
        .flat_map_iter(|hit| {
            let mut local: Vec<SourceAnalysisCandidate> = Vec::new();
            let Some(source_match) = source_finding_match(hit, pack) else {
                return local.into_iter();
            };
            let Some(start) = func_id_for_match(hit, &func_ids) else {
                return local.into_iter();
            };
            let graph = global
                .decl_of(SymbolId::new(start.raw()))
                .map(|decl| {
                    let value_flow = ws
                        .value_flow()
                        .graph_for_with_caches(start, ws.db(), source_graph_caches);
                    let seeds = source_seed_set(pack, hit, decl, Some(value_flow.as_ref()));
                    let output_arg_names = output_arg_names_for_match(pack, hit, decl);
                    let anchor = if rule_match_kind_is_param(pack, &hit.rule_id) {
                        None
                    } else {
                        Some(hit.span)
                    };
                    let graph_key = (
                        start,
                        sorted_seed_key_with_anchor(&seeds, anchor, &output_arg_names),
                    );
                    // L1: per-invocation map. Drop the read guard
                    // before any potential write upgrade.
                    let cached = local_graphs.read().get(&graph_key).cloned();
                    if let Some(arc) = cached {
                        return (*arc).clone();
                    }
                    // L2: workspace-wide TaintGraphIndex.
                    if let Some(arc) = workspace_taint_index.get(start, &graph_key.1) {
                        local_graphs
                            .write()
                            .entry(graph_key.clone())
                            .or_insert(arc.clone());
                        return (*arc).clone();
                    }
                    let computed = Arc::new(exact_source_seed_graph(
                        start,
                        &seeds,
                        &source_graph_config,
                        ws.db(),
                        source_graph_caches,
                        ws,
                        anchor,
                        &output_arg_names,
                    ));
                    let canonical = workspace_taint_index.insert_if_absent(
                        start,
                        graph_key.1.clone(),
                        computed,
                    );
                    local_graphs
                        .write()
                        .entry(graph_key)
                        .or_insert(canonical.clone());
                    (*canonical).clone()
                })
                .unwrap_or_else(|| ws.dataflow().graph_for(start, ws.db()).as_ref().clone());
            let lineages = enumerate_tainted_source_lineages(&graph.call_records, start, 6, 24);
            if lineages.is_empty() {
                let path = vec![start];
                let Some(chain_names) = chain_names_for_path(ws, &path) else {
                    return local.into_iter();
                };
                let taint_path = Vec::new();
                let flow_id = flow_id_for_taint_path(&chain_names, &taint_path);
                local.push(SourceAnalysisCandidate {
                    source: source_match.clone(),
                    path,
                    flow_id,
                    chain_names,
                    taint_path,
                });
                return local.into_iter();
            }
            for lineage in lineages {
                let terminal = lineage.last().map(|record| record.callee).unwrap_or(start);
                let Some(path) = chain_funcs_for_lineage(&lineage, start, terminal) else {
                    continue;
                };
                let Some(chain_names) = chain_names_for_path(ws, &path) else {
                    continue;
                };
                let taint_path = taint_path_for_lineage(ws, &lineage, None);
                let flow_id = flow_id_for_taint_path(&chain_names, &taint_path);
                local.push(SourceAnalysisCandidate {
                    source: source_match.clone(),
                    path,
                    flow_id,
                    chain_names,
                    taint_path,
                });
            }
            local.into_iter()
        })
        .collect();

    // Single-threaded dedupe pass — preserves the first-occurrence
    // semantics of the prior sequential `seen` set across the
    // par-collected candidates. Order is stable because
    // `flat_map_iter` preserves input order on collection.
    let mut seen: AHashSet<(String, String, u32, String)> = AHashSet::new();
    let mut candidates: Vec<SourceAnalysisCandidate> = Vec::with_capacity(parallel_candidates.len());
    for candidate in parallel_candidates {
        let dedupe_key = (
            candidate.source.rule_id.clone(),
            candidate.source.file.clone(),
            candidate.source.line,
            candidate.flow_id.clone(),
        );
        if seen.insert(dedupe_key) {
            candidates.push(candidate);
        }
    }
    for _ in 0..source_hits.len() {
        on_progress(AnalysisProgress::PhaseTicked);
    }
    on_progress(AnalysisProgress::PhaseFinished);

    Ok(SourceAnalysisReport {
        candidates: combine_source_analysis_candidates(candidates),
        source_rule_count: sources.len(),
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

fn function_ids_by_lang_file_name(ws: &Workspace) -> AHashMap<(String, String, String), FuncId> {
    let global = ws.db().global_index();
    let mut out = AHashMap::new();
    for file in global.all_files() {
        let Some(adapter) = ws.db().adapter_for(file) else {
            continue;
        };
        let lang = adapter.language_id().as_str().to_string();
        let file_path = ws
            .vfs()
            .path(file)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        for decl in global.decls_in(file) {
            out.entry((lang.clone(), file_path.clone(), decl.name.clone()))
                .or_insert_with(|| FuncId::new(decl.symbol.raw()));
        }
    }
    out
}

fn func_id_for_match(
    hit: &RuleMatch,
    func_ids: &AHashMap<(String, String, String), FuncId>,
) -> Option<FuncId> {
    let name = hit.enclosing_fn.as_ref()?;
    func_ids
        .get(&(hit.language.clone(), hit.file.clone(), name.clone()))
        .copied()
}

fn enumerate_tainted_source_lineages(
    records: &[TaintedCallEdge],
    source: FuncId,
    max_extra: usize,
    max_paths: usize,
) -> Vec<Vec<&TaintedCallEdge>> {
    if max_extra == 0 || max_paths == 0 || !records.iter().any(|record| record.trace_id != 0) {
        return Vec::new();
    }
    let child_trace_ids: AHashSet<u64> = records
        .iter()
        .filter_map(|record| record.parent_trace_id)
        .collect();
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
        let Some(mut lineage) = lineage_records_for_trace_id(records, endpoint.trace_id) else {
            continue;
        };
        if lineage.first().is_none_or(|record| record.caller != source) {
            continue;
        }
        if lineage.len() > max_extra {
            lineage.truncate(max_extra);
        }
        let key: Vec<u64> = lineage.iter().map(|record| record.trace_id).collect();
        if !key.is_empty() && seen.insert(key) {
            out.push(lineage);
            if out.len() >= max_paths {
                break;
            }
        }
    }
    out
}

fn chain_precision_for_records(records: &[&TaintedCallEdge]) -> Precision {
    records.iter().fold(Precision::Exact, |precision, record| {
        precision.meet(record.precision)
    })
}

fn lineage_records_for_call<'a>(
    records: &'a [TaintedCallEdge],
    terminal_call: &TaintedCall,
) -> Option<Vec<&'a TaintedCallEdge>> {
    match terminal_call.parent_trace_id {
        Some(trace_id) => lineage_records_for_trace_id(records, trace_id),
        None => Some(Vec::new()),
    }
}

fn lineage_records_for_trace_id(records: &[TaintedCallEdge], trace_id: u64) -> Option<Vec<&TaintedCallEdge>> {
    let mut current = Some(trace_id);
    let mut lineage = Vec::new();
    let mut seen = AHashSet::new();
    let mut by_id: AHashMap<u64, &TaintedCallEdge> = AHashMap::new();
    for record in records {
        if record.trace_id != 0 {
            by_id.entry(record.trace_id).or_insert(record);
        }
    }
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
fn rewrite_chain_with_canonical_path(
    primary: Vec<FuncId>,
    all_records: &[TaintedCallEdge],
    source_func: FuncId,
    terminal_func: FuncId,
) -> Vec<FuncId> {
    let primary_synth = chain_synth_count(&primary, all_records);
    if primary_synth == 0 {
        return primary;
    }
    let Some(alt) = best_chain_through_real_edges(all_records, source_func, terminal_func) else {
        return primary;
    };
    // Reject degenerate alternatives (shorter than primary).
    if alt.len() < primary.len() {
        return primary;
    }
    let alt_synth = chain_synth_count(&alt, all_records);
    let primary_real = primary.len().saturating_sub(1).saturating_sub(primary_synth);
    let alt_real = alt.len().saturating_sub(1).saturating_sub(alt_synth);
    // Prefer chain with more real hops (more informative call
    // sequence). On ties, prefer fewer synthetic hops. On further
    // ties, keep the primary (parent_trace_id-derived chain).
    let alt_is_better = alt_real > primary_real
        || (alt_real == primary_real && alt_synth < primary_synth);
    if alt_is_better {
        alt
    } else {
        primary
    }
}

fn chain_synth_count(chain: &[FuncId], all_records: &[TaintedCallEdge]) -> usize {
    fn is_synthetic(rec: &TaintedCallEdge) -> bool {
        rec.tainted_args
            .first()
            .map(|a| a.index == usize::MAX || a.index == 255)
            .unwrap_or(false)
    }
    let mut count = 0;
    for window in chain.windows(2) {
        let (a, b) = (window[0], window[1]);
        let mut found_any = false;
        let mut found_real = false;
        for r in all_records {
            if r.caller == a && r.callee == b {
                found_any = true;
                if !is_synthetic(r) {
                    found_real = true;
                    break;
                }
            }
        }
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
    all_records: &[TaintedCallEdge],
    source_func: FuncId,
    terminal_func: FuncId,
) -> Option<Vec<FuncId>> {
    const MAX_HOPS: usize = 16;
    fn is_synthetic(rec: &TaintedCallEdge) -> bool {
        rec.tainted_args
            .first()
            .map(|a| a.index == usize::MAX || a.index == 255)
            .unwrap_or(false)
    }
    fn score(synth: u32, real: u32) -> i64 {
        100i64 * (synth as i64) - (real as i64)
    }
    let mut adj: AHashMap<FuncId, Vec<(FuncId, bool)>> = AHashMap::default();
    for r in all_records {
        adj.entry(r.caller).or_default().push((r.callee, is_synthetic(r)));
    }
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    // State: (score, synth, real, path). Pop lowest score first.
    let mut heap: BinaryHeap<Reverse<(i64, u32, u32, Vec<FuncId>)>> = BinaryHeap::new();
    heap.push(Reverse((score(0, 0), 0, 0, vec![source_func])));
    let mut best_score: AHashMap<FuncId, i64> = AHashMap::default();
    best_score.insert(source_func, score(0, 0));
    while let Some(Reverse((s, synth, real, path))) = heap.pop() {
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
        let Some(neighbors) = adj.get(&cur) else { continue };
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
            heap.push(Reverse((next_score, next_synth, next_real, next_path)));
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

fn propagation_step_for_edge(ws: &Workspace, record: &TaintedCallEdge) -> TaintPropagationStep {
    let (file, line, column) = resolve_span_location(ws, record.call_span);
    TaintPropagationStep {
        caller: func_display_name(ws, record.caller),
        callee: func_display_name(ws, record.callee),
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
    TaintPropagationStep {
        caller: func_display_name(ws, call.caller),
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
        .map(|record| propagation_step_for_edge(ws, record))
        .collect();
    if let Some(call) = terminal_call {
        path.push(propagation_step_for_terminal_call(ws, call));
    }
    path
}

fn func_display_name(ws: &Workspace, func: FuncId) -> String {
    ws.db()
        .global_index()
        .decl_of(SymbolId::new(func.raw()))
        .map(|decl| decl.name.clone())
        .unwrap_or_else(|| format!("func#{}", func.raw()))
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

fn combine_source_analysis_candidates(
    flows: Vec<SourceAnalysisCandidate>,
) -> Vec<CombinedSourceAnalysisCandidate> {
    let mut groups: Vec<CombinedSourceAnalysisCandidate> = Vec::new();
    let mut index: AHashMap<String, usize> = AHashMap::new();
    for item in flows {
        let key = item.flow_id.clone();
        if let Some(&idx) = index.get(&key) {
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
            additional_sources: Vec::new(),
        });
    }
    groups
}

fn chain_names_for_path(ws: &Workspace, path: &[FuncId]) -> Option<Vec<String>> {
    let global = ws.db().global_index();
    path.iter()
        .map(|func| {
            global
                .decl_of(SymbolId::new(func.raw()))
                .map(|decl| decl.name.clone())
        })
        .collect()
}

/// True when two source-side `FindingMatch`es refer to the exact
/// same call-site in the source code. Used during finding combination
/// to avoid pushing duplicate sources onto a group.
fn same_source_site(a: &FindingMatch, b: &FindingMatch) -> bool {
    a.rule_id == b.rule_id && a.file == b.file && a.line == b.line && a.column == b.column
}

/// True when two sink-side `FindingMatch`es refer to the exact same
/// call-site. Symmetric counterpart to [`same_source_site`].
fn same_sink_site(a: &FindingMatch, b: &FindingMatch) -> bool {
    a.rule_id == b.rule_id && a.file == b.file && a.line == b.line && a.column == b.column
}

fn combine_findings_by_source_flow(findings: Vec<FindingWithChain>) -> Vec<CombinedFindingWithChain> {
    let mut groups: Vec<CombinedFindingWithChain> = Vec::new();
    let mut index: AHashMap<String, usize> = AHashMap::new();

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
    let chain = f.chain_display.join("\0");
    format!(
        "{}\0{}\0{}\0{}\0{}",
        f.language,
        f.group_id.as_deref().unwrap_or(""),
        f.representative_flow_id.as_deref().unwrap_or(""),
        chain,
        f.sink.rule_id
    )
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
    // Status merge: the LEAST-mitigated chain wins. If any chain in
    // this group is unsanitized, the group is unsanitized — finding a
    // sanitizer on one path doesn't make the others safe.
    group.finding.status = group.finding.status.merge(incoming.status);
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
    sources.sort_by(|a, b| {
        a.rule_id
            .cmp(&b.rule_id)
            .then_with(|| (a.file.as_str(), a.line, a.column).cmp(&(b.file.as_str(), b.line, b.column)))
    });
    group.finding.source = sources[0].clone();
    group.additional_sources = sources.into_iter().skip(1).collect();

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
/// 1. **Index funcs by (lang, file, name)** — per-FuncId sanitizer
///    attribution avoids the cross-bridge over-counting that happens
///    when sanitizers are indexed by bare name alone.
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
    on_progress: &mut F,
) -> Vec<FindingWithChain>
where
    F: FnMut(AnalysisProgress),
{
    // ---- Phase 1: index funcs by (lang, file, name) ----
    let global = ws.db().global_index();
    // Index every decl by `(lang, file, name)` first so we can look
    // up sanitizers by the SPECIFIC FuncId of their enclosing
    // function. Indexing sanitizers by NAME alone (the previous
    // behaviour) cross-bridged: jackson-core has `write()` in
    // dozens of files; gin has `serveError()` in tests and prod;
    // any sanitizer match in any function named `write` was being
    // credited against every chain whose hops included a function
    // also called `write`, regardless of file. That triggered
    // huge "wrong-context" inflation against sinks whose tag was
    // unrelated to the credited sanitizer.
    let mut funcs_by_key: AHashMap<(String, String, String), FuncId> = AHashMap::new();
    for file in global.all_files() {
        let Some(adapter) = ws.db().adapter_for(file) else {
            continue;
        };
        let lang = adapter.language_id().as_str().to_string();
        let file_path = ws
            .vfs()
            .path(file)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        for decl in global.decls_in(file) {
            let fid = FuncId::new(decl.symbol.raw());
            let key = (lang.clone(), file_path.clone(), decl.name.clone());
            funcs_by_key.entry(key).or_insert(fid);
        }
    }
    let mut san_by_func: AHashMap<FuncId, Vec<&RuleMatch>> = AHashMap::new();
    for s in sanitizers {
        let Some(fname) = s.enclosing_fn.as_deref() else {
            continue;
        };
        let key = (s.language.clone(), s.file.clone(), fname.to_string());
        if let Some(&fid) = funcs_by_key.get(&key) {
            san_by_func.entry(fid).or_default().push(s);
        }
    }
    let mut sink_by_func: AHashMap<FuncId, Vec<&RuleMatch>> = AHashMap::new();
    for snk in sinks {
        let Some(snk_fn) = snk.enclosing_fn.as_deref() else {
            continue;
        };
        let sink_key = (snk.language.clone(), snk.file.clone(), snk_fn.to_string());
        let Some(&sink_func_id) = funcs_by_key.get(&sink_key) else {
            continue;
        };
        sink_by_func.entry(sink_func_id).or_default().push(snk);
    }
    if source_hits.is_empty() || sink_by_func.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    // Materialise per-source value-flow seeds in parallel. On
    // OWASP this loop runs 2,740 times sequentially without rayon
    // because each `graph_for_with_caches` faults a per-function
    // value-flow graph under a single RwLock. The cache is
    // RwLock-backed and order-independent (cache-fill races on the
    // same key produce identical values — see `InterTaintCaches`
    // doc), so the fan-out is a pure scheduling change. Input
    // ordering is preserved: `source_hits` is sorted upstream
    // (`sort_matches`) and `par_iter().filter_map().collect()` is
    // order-preserving, so downstream `idx`-keyed dedup
    // (`emitted_for_source_sink_flow`) sees identical idx values.
    use rayon::prelude::*;
    let source_entries: Vec<(&RuleMatch, FuncId, TokenSet)> = source_hits
        .par_iter()
        .filter_map(|src| {
            let src_key = match_func_key(src)?;
            let &src_func_id = funcs_by_key.get(&src_key)?;
            let src_decl = global.decl_of(SymbolId::new(src_func_id.raw()))?;
            let value_flow = ws.value_flow().graph_for_with_caches(
                src_func_id,
                ws.db(),
                ws.inter_taint_caches(),
            );
            let seeds = source_seed_set(pack, src, src_decl, Some(value_flow.as_ref()));
            if seeds.is_empty() {
                return None;
            }
            Some((src, src_func_id, seeds))
        })
        .collect();
    let mut source_work: Vec<(&RuleMatch, FuncId, TokenSet)> =
        Vec::with_capacity(source_entries.len());
    let mut source_groups: AHashMap<FuncId, Vec<usize>> = AHashMap::new();
    for (src, src_func_id, seeds) in source_entries {
        let idx = source_work.len();
        source_work.push((src, src_func_id, seeds));
        source_groups.entry(src_func_id).or_default().push(idx);
    }

    on_progress(AnalysisProgress::PhaseStarted {
        label: "checking source returns",
        total: source_work.len() as u64,
    });
    // Parallel "does this seed reach a Return?" pass. Dedup keys
    // first so each unique `(src_func_id, sorted_seed_key)` runs
    // only once, mirroring the previous sequential cache. Then
    // fan out across rayon — `source_seed_reaches_return` consults
    // the workspace value-flow cache (RwLock-backed, thread-safe)
    // and falls back to the engine via the workspace InterTaintCaches
    // singleton, also thread-safe. `on_progress` isn't `Sync`, so
    // ticks are replayed sequentially after the parallel collect.
    let mut unique_keys: Vec<(FuncId, Vec<String>)> = Vec::new();
    {
        let mut seen: AHashSet<(FuncId, Vec<String>)> = AHashSet::new();
        for (_, src_func_id, seeds) in source_work.iter() {
            let key = (*src_func_id, sorted_seed_key(seeds));
            if seen.insert(key.clone()) {
                unique_keys.push(key);
            }
        }
    }
    let returning_pairs: Vec<((FuncId, Vec<String>), bool)> = unique_keys
        .par_iter()
        .map(|key| {
            let seeds: TokenSet = key.1.iter().cloned().collect();
            let returns = source_seed_reaches_return(key.0, &seeds, ws, intra_worklist_cap);
            (key.clone(), returns)
        })
        .collect();
    let returning_map: AHashMap<(FuncId, Vec<String>), bool> = returning_pairs.into_iter().collect();
    let mut source_returning_indices: AHashSet<usize> = AHashSet::new();
    for (idx, (_, src_func_id, seeds)) in source_work.iter().enumerate() {
        let key = (*src_func_id, sorted_seed_key(seeds));
        if *returning_map.get(&key).unwrap_or(&false) {
            source_returning_indices.insert(idx);
        }
    }
    for _ in 0..source_work.len() {
        on_progress(AnalysisProgress::PhaseTicked);
    }
    on_progress(AnalysisProgress::PhaseFinished);

    // Schedule each transitive caller of every source-returning
    // function as an additional entry so the inter pass processes
    // them too. The engine walks DOWNWARD through callees starting
    // from the source-bearing function; without scheduling the
    // callers, helper functions like `def get_user_input(): return
    // os.getenv(...)` never propagate their tainted return into
    // the variable that captured the call result. Bounded depth so
    // deep call chains don't explode the per-entry pair count.
    //
    // Crucially, source-bearing is not enough. A helper that reads a
    // file or request but returns only a status must not taint every
    // caller branch that happens to be reachable from the same
    // function. Only helpers where the matched source reaches a
    // Return event are eligible for caller scheduling.
    const TRANSITIVE_CALLER_DEPTH: u32 = 4;
    // The transitive caller closure is rulepack-independent — it's
    // a pure function of the resolved call graph — so we let the
    // workspace cache it once and consult it here. Per-source-
    // returning func, look up the cached closure, then attribute
    // each transitive caller back to the source's `orig_idx` so
    // lineage stays correct (without the orig_idx tracking, the
    // old fallback could attach an unrelated source rule's lineage
    // to a chain — the canonical bug was a Redis report titled
    // "source in ACLLoadFromFile" but rendered as starting at
    // `aclCommand`).
    let cg = ws.cached_resolved_call_graph();
    let transitive_callers = ws.transitive_callers();
    let mut visited: AHashSet<(FuncId, usize)> = source_work
        .iter()
        .enumerate()
        .filter(|(idx, _)| source_returning_indices.contains(idx))
        .map(|(idx, (_, func, _))| (*func, idx))
        .collect();
    // Iterate `(func, orig_idx)` pairs in deterministic order so the
    // resulting `source_work` extension order is stable across runs.
    let mut seed_pairs: Vec<(FuncId, usize)> = source_work
        .iter()
        .enumerate()
        .filter(|(idx, _)| source_returning_indices.contains(idx))
        .map(|(idx, (_, func, _))| (*func, idx))
        .collect();
    seed_pairs.sort_by_key(|(func, idx)| (func.raw(), *idx));
    for &(seed_func, orig_idx) in &seed_pairs {
        let callers = transitive_callers.callers_of(&cg, seed_func, TRANSITIVE_CALLER_DEPTH);
        for caller_func in callers.iter().copied() {
            if !visited.insert((caller_func, orig_idx)) {
                continue;
            }
            let (orig_src, _, _) = &source_work[orig_idx];
            // Empty seed — the inter pass's `apply_return_taint`
            // consults the callee's `returns_external` and taints
            // the assignment LHS when it sees
            // `var = source_helper()`. A non-empty seed risks
            // pre-tainting unrelated identifiers in the caller.
            let new_idx = source_work.len();
            source_work.push((*orig_src, caller_func, TokenSet::default()));
            source_groups.entry(caller_func).or_default().push(new_idx);
        }
    }

    // Functions the security layer has proven source-returning.
    // The taint engine consults this set to decide whether
    // `var = helper()` should auto-taint `var` (cross-file recall
    // for source-returning helpers, task #95). The engine never
    // populates this on its own — empty set ⇒ engine produces zero
    // propagation records on empty seeds (engine invariant).
    let source_bearing_functions: AHashSet<FuncId> = source_returning_indices
        .iter()
        .filter_map(|idx| source_work.get(*idx).map(|(_, func, _)| *func))
        .collect();
    let config = InterTaintConfig {
        sanitizers: TokenSet::default(),
        budget: interprocedural_budget.unwrap_or_else(|| InterTaintConfig::default().budget),
        intra_worklist_cap,
        source_bearing_functions,
        clean_output_overwrites: clean_output_overwrites_from_rulepack(pack),
        source_output_args: source_output_args_from_rulepack(pack),
        receiver_state_propagations: receiver_state_propagations_from_rulepack(pack),
        ..Default::default()
    };
    let taint_caches = ws.inter_taint_caches();
    // Workspace-wide source-seeded graph index (Stage 6). Lifted out
    // of the per-invocation map so a second `taint-analysis` /
    // `source-analysis` against the same `(workspace, rulepack)`
    // becomes a lookup. Within ONE invocation the inner per-thread
    // `parking_lot::RwLock` still owns the dedup so rayon workers
    // probe locally before falling back to the workspace index.
    let workspace_taint_index = ws.taint_index();
    // Per-invocation fallback map for the rare case where the
    // workspace index is opted out (e.g. clear_for_config invalidated
    // mid-scan). Same shape as Stage 1's design.
    let exact_graphs: parking_lot::RwLock<
        AHashMap<(FuncId, Vec<String>), std::sync::Arc<EntryTaintGraph>>,
    > = parking_lot::RwLock::new(AHashMap::new());
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
    // `rayon::prelude::*` is already in scope from the
    // earlier `source_entries` parallel pass.
    let parallel_out: Vec<FindingWithChain> = source_groups_sorted
        .par_iter()
        .flat_map_iter(|&(src_func_id, indices)| {
            let mut group_out: Vec<FindingWithChain> = Vec::new();
            let mut emitted_for_source_sink_flow: AHashSet<(usize, String, u32, u64, u64, Option<u64>)> =
                AHashSet::new();
            for &idx in indices {
                let (src, _, seeds) = &source_work[idx];
                let output_arg_names = global
                    .decl_of(SymbolId::new(src_func_id.raw()))
                    .map(|d| output_arg_names_for_match(pack, src, d))
                    .unwrap_or_default();
                let anchor = if rule_match_kind_is_param(pack, &src.rule_id) {
                    None
                } else {
                    Some(src.span)
                };
                let graph_key = (
                    src_func_id,
                    sorted_seed_key_with_anchor(seeds, anchor, &output_arg_names),
                );
                // Lookup order:
                //   1. per-invocation `exact_graphs` (lock-free probe path)
                //   2. workspace-wide taint index (cross-invocation cache)
                //   3. compute, populate both layers
                // Read guards are scoped to a single statement to
                // avoid the parking_lot read→write deadlock that
                // tripped Stage 1.
                let cached = exact_graphs.read().get(&graph_key).cloned();
                let graph: std::sync::Arc<EntryTaintGraph> = if let Some(hit) = cached {
                    hit
                } else if let Some(hit) =
                    workspace_taint_index.get(src_func_id, &graph_key.1)
                {
                    // Hydrate the local map so subsequent probes hit
                    // the lock-free path.
                    let mut write = exact_graphs.write();
                    write.entry(graph_key.clone()).or_insert(hit).clone()
                } else {
                    let computed = std::sync::Arc::new(exact_source_seed_graph(
                        src_func_id,
                        seeds,
                        &config,
                        ws.db(),
                        taint_caches,
                        ws,
                        anchor,
                        &output_arg_names,
                    ));
                    // Stage 6: publish to the workspace index first
                    // so concurrent invocations can pick it up.
                    let canonical = workspace_taint_index.insert_if_absent(
                        src_func_id,
                        graph_key.1.clone(),
                        computed.clone(),
                    );
                    let mut write = exact_graphs.write();
                    write.entry(graph_key).or_insert(canonical).clone()
                };
                if graph.tainted_calls.is_empty() {
                    continue;
                }
            // Span set of every recorded tainted call on this
            // source graph — sanitizer credit pass uses it to
            // require data-flow connectivity rather than mere
            // chain co-occurrence.
            let tainted_call_spans: AHashSet<Span> =
                graph.tainted_calls.iter().map(|c| c.call_span).collect();
            for call in &graph.tainted_calls {
                let Some(candidate_sinks) = sink_by_func.get(&call.caller) else {
                    continue;
                };
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
                    if !source_can_precede_sink(src, snk) {
                        continue;
                    }
                    if any_span_match {
                        if !spans_overlap(call.call_span, snk.span) {
                            continue;
                        }
                    } else if !tainted_call_matches_sink(call, snk) {
                        continue;
                    }
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
                    let lineage_records = lineage_records_for_call(&graph.call_records, call);
                    let lineage_chain = lineage_records.as_ref().and_then(|records| {
                        let primary =
                            chain_funcs_for_lineage(records, src_func_id, call.caller)?;
                        // Chain-quality upgrade: when the lineage walk
                        // anchored on `parent_trace_id` goes through
                        // synthetic edges (Phase 3c field-flow stitches,
                        // Phase 3d receiver-method propagation, or
                        // Return back-edges — all sentinel
                        // `arg_idx == usize::MAX`), search the full
                        // record set for an alternative path that has
                        // fewer synthetic hops while covering at least
                        // as many distinct functions. Picks the
                        // canonical call sequence over data-flow
                        // detours (e.g. Java
                        // `handle → orchestrate → persist → run` over
                        // `handle → orchestrate → cmd → run`).
                        Some(rewrite_chain_with_canonical_path(
                            primary,
                            &graph.call_records,
                            src_func_id,
                            call.caller,
                        ))
                    });
                    let (Some(records), Some(chain_funcs)) = (lineage_records.as_ref(), lineage_chain) else {
                        continue;
                    };
                    let mut chain_precision = chain_precision_for_records(records);
                    let taint_path = taint_path_for_lineage(ws, records, Some(call));
                    if graph.saturated {
                        chain_precision = chain_precision.meet(Precision::OverApproximate);
                    }
                    let chain_names: Vec<String> = chain_funcs
                        .iter()
                        .filter_map(|&f| global.decl_of(SymbolId::new(f.raw())).map(|d| d.name.clone()))
                        .collect();
                    let group_id = group_id_for_taint_path(&chain_names, &taint_path);
                    let flow_id = flow_id_for_taint_path(&chain_names, &taint_path);
                    if !emitted_for_source_sink_flow.insert(source_sink_flow_emission_key(idx, snk, call)) {
                        continue;
                    }
                    let sink_tainted_args: Vec<TaintedArgInfo> = call
                        .tainted_args
                        .iter()
                        .map(|a| TaintedArgInfo {
                            index: a.index,
                            value_text: a.value_text.clone(),
                        })
                        .collect();
                    if let Some(f) = make_finding(
                        src,
                        snk,
                        pack,
                        FindingBuildContext {
                            group_id: Some(group_id),
                            flow_id: Some(flow_id),
                            chain_funcs: &chain_funcs,
                            chain_names: chain_names.clone(),
                            san_by_func: &san_by_func,
                            tainted_call_spans: &tainted_call_spans,
                            sink_tainted_args,
                            taint_path,
                            precision: chain_precision,
                        },
                    ) {
                        group_out.push(FindingWithChain {
                            finding: f,
                            chain_funcs,
                        });
                    }
                }
            }
            }
            group_out
        })
        .collect();
    out.extend(parallel_out);
    // Progress callback isn't `Send`, so the parallel pass can't tick
    // mid-flight. Replay one tick per group now so consumers see the
    // bar advance to the declared total before the phase finishes.
    for _ in 0..total_groups {
        on_progress(AnalysisProgress::PhaseTicked);
    }
    on_progress(AnalysisProgress::PhaseFinished);
    out
}

/// Build a deterministic key for a seed token set so the same seeds
/// hash to the same `exact_graphs` cache slot regardless of insertion
/// order. AHashSet iteration is randomised per process, which would
/// otherwise miss obvious cache hits.
fn sorted_seed_key(seeds: &TokenSet) -> Vec<String> {
    let mut sorted: Vec<String> = seeds.iter().cloned().collect();
    sorted.sort();
    sorted
}

/// Variant of [`sorted_seed_key`] that additionally encodes the
/// anchor span and the configured output-arg name list into the
/// cache key. The taint-graph cache is keyed on `(FuncId, Vec<String>)`,
/// and the IDG-driven seed builder threads `anchor`/`output_arg_names`
/// into the per-source graph computation — but the resulting graph
/// can differ between two source matches on the same function with
/// the same name seeds but different anchor spans (e.g. two
/// `req.getParameter("…")` calls on adjacent lines produce different
/// IDG seed-node sets, hence different forward closures). Without
/// the anchor in the key, the first insert wins and the second
/// match wedges into the wrong cached graph — that's the divergence
/// behind the CLI/SDK parity gap on Java micro. Prefixing the key
/// with `__anchor@file:start..end` is a no-op when anchor is `None`
/// (kind: param sources fall through to name-based seeding).
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
    bonsai_taint::entry_taint_graph_from_idg(
        source_func,
        seeds,
        source_anchor,
        output_arg_names,
        &config.receiver_state_propagations,
        db,
        idg.as_ref(),
    )
}

fn source_seed_reaches_return(
    source_func: FuncId,
    seeds: &TokenSet,
    ws: &Workspace,
    intra_worklist_cap: Option<u32>,
) -> bool {
    if seeds.is_empty() {
        return false;
    }
    // Fast path: a hash-set lookup against the precomputed
    // `returning_seed_names` set built when the value-flow graph
    // for `source_func` was constructed. This collapses the
    // per-seed forward-closure walk into a single intersection.
    let returning_names = ws.value_flow().returning_seed_names(
        source_func,
        ws.db(),
        ws.inter_taint_caches(),
    );
    if !returning_names.is_empty() && seeds.iter().any(|s| returning_names.contains(s)) {
        return true;
    }
    // Engine fallback path. The engine's seed-by-name semantics
    // matches the source_seed_set output exactly; switching this
    // to IDG would require span-based seeding (Phase 8 follow-on).
    let config = InterTaintConfig {
        sanitizers: TokenSet::default(),
        budget: 64,
        intra_worklist_cap,
        source_bearing_functions: AHashSet::default(),
        ..Default::default()
    };
    let result = bonsai_taint::interprocedural_taint_to_completion_with_caches(
        source_func,
        seeds,
        &config,
        ws.db(),
        ws.inter_taint_caches(),
    );
    result
        .tainted_calls
        .iter()
        .any(|call| call.caller == source_func && call.kind == TaintedCallKind::Return)
}

/// True when the source could syntactically reach the sink — same-fn
/// flows must have the source statement BEFORE the sink, otherwise
/// the supposed flow runs backwards in time. Cross-fn cases always
/// pass since the call graph models the temporal order separately.
fn source_can_precede_sink(src: &RuleMatch, snk: &RuleMatch) -> bool {
    if src.file != snk.file || src.enclosing_fn != snk.enclosing_fn {
        return true;
    }
    src.line < snk.line || (src.line == snk.line && src.column <= snk.column)
}

/// True when the sanitizer's match span overlaps a call recorded
/// by the taint engine as carrying tainted arguments. Without this,
/// any rule whose call site happens to live on the source-to-sink
/// chain would be credited even when its arguments have nothing to
/// do with the tainted value — see WC#4 in the Redis evaluation
/// where a `pthread_mutex_lock` (lock-acquire tag) was being
/// flagged as a wrong-context sanitizer for a `memcpy` sink.
fn sanitizer_call_overlaps_tainted_call(san: &RuleMatch, tainted_call_spans: &AHashSet<Span>) -> bool {
    tainted_call_spans
        .iter()
        .any(|span| spans_overlap(*span, san.span))
}

fn sanitizer_is_nested_in_tainted_sink_arg(san: &RuleMatch, sink_tainted_args: &[TaintedArgInfo]) -> bool {
    let text = san.match_text.trim();
    !text.is_empty() && sink_tainted_args.iter().any(|arg| arg.value_text.contains(text))
}

/// True when a sanitizer match could plausibly attach to the
/// source→sink chain — must come AFTER the source within the
/// source's enclosing fn, and BEFORE the sink within the sink's
/// enclosing fn. A sanitizer nested inside a tainted sink argument is
/// semantically before the sink execution even though its callee token
/// appears after the sink callee token. Cross-fn sanitizers always pass
/// this gate; the chain-hop check elsewhere handles inter-fn placement.
fn sanitizer_can_attach(
    src: &RuleMatch,
    san: &RuleMatch,
    snk: &RuleMatch,
    sink_tainted_args: &[TaintedArgInfo],
) -> bool {
    if san.file == src.file && san.enclosing_fn == src.enclosing_fn && !match_precedes_or_same(src, san) {
        return false;
    }
    if san.file == snk.file
        && san.enclosing_fn == snk.enclosing_fn
        && !match_precedes_or_same(san, snk)
        && !sanitizer_is_nested_in_tainted_sink_arg(san, sink_tainted_args)
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

/// Build the `(language, file, fn_name)` lookup key for a matcher
/// hit. Returns `None` when the matcher couldn't resolve an
/// enclosing function — those hits can't be mapped to a `FuncId`.
fn match_func_key(hit: &RuleMatch) -> Option<(String, String, String)> {
    Some((hit.language.clone(), hit.file.clone(), hit.enclosing_fn.clone()?))
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
/// concrete carrier names at the source's call site. For
/// `fgets(buf, sz, stdin)` with `output_args=[0]`, returns
/// `["buf"]` — the IDG seeder then includes post-call reads/writes
/// of `buf` so the side-effect taint flows into downstream consumers.
fn output_arg_names_for_match(
    pack: &Rulepack,
    src: &RuleMatch,
    decl: &bonsai_lang_api::Decl,
) -> Vec<String> {
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
    fn find_call<'a>(
        events: &'a [FlowEvent],
        target: bonsai_common::Span,
    ) -> Option<&'a FlowEvent> {
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
                    if let Some(callee) = source_call.as_deref() {
                        // Only seed the unqualified TAIL of the source
                        // call, not the full qualified form. Adding
                        // `os.getenv` as a seed token taints the bare
                        // base `os` via
                        // `state_qualified_token_matches_text`, which
                        // then conflates every other `os.<x>` call in
                        // the same function (Task #279). The tail
                        // (`getenv`) carries the same matching
                        // ergonomics for downstream sink-name rules
                        // without polluting the receiver namespace.
                        if let Some(tail) = callee.rsplit(&['.', ':'][..]).next() {
                            if !tail.is_empty() {
                                out.insert(tail.to_string());
                            }
                        }
                    }
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
    if let Some(tail) = trimmed.rsplit(&['.', ':'][..]).next() {
        if tail != trimmed && !tail.is_empty() {
            out.insert(tail.to_string());
        }
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
    let func_ids = function_ids_by_lang_file_name(ws);
    let mut emitted: AHashSet<(String, String, u32, u32)> = AHashSet::new();
    let mut out = Vec::new();
    for snk in sinks {
        let site_key = (snk.rule_id.clone(), snk.file.clone(), snk.line, snk.column);
        if taint_sink_sites.contains(&site_key) || !emitted.insert(site_key) {
            continue;
        }
        let chain_funcs: Vec<FuncId> = match_func_key(snk)
            .and_then(|key| func_ids.get(&key).copied())
            .into_iter()
            .collect();
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
    Some(Finding {
        finding_id,
        language: snk.language.clone(),
        source,
        sink,
        sanitizers_seen: Vec::new(),
        group_id: Some(group_id.clone()),
        representative_flow_id: Some(flow_id),
        chain_display,
        taint_path: Vec::new(),
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
    if rule.kind != RuleKind::Sink || !rule.enabled || rule_has_taint_predicate(rule) {
        return false;
    }
    if rule.match_spec.kind == MatchKind::Missing {
        return true;
    }
    let tag = rule.tag.as_deref().unwrap_or_default();
    matches!(
        tag,
        "weak-crypto"
            | "weak-randomness"
            | "weak-tls"
            | "cors"
            | "csrf"
            | "auth-bypass"
            | "insecure-temp-file"
            | "memory-safety"
            | "race"
            | "secure-cookie"
    ) || rule.cwe.iter().any(|cwe| {
        matches!(
            cwe.as_str(),
            "CWE-327" | "CWE-328" | "CWE-330" | "CWE-338" | "CWE-614"
        )
    })
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
            if !sanitizer_can_attach(src, sanitizer_match, snk, &context.sink_tainted_args) {
                continue;
            }
            // Data-flow-aware credit: the sanitizer's call site must
            // itself be a tainted call on this graph. Without this
            // gate any rule firing somewhere on the chain credits the
            // finding even when its argument has nothing to do with
            // the source's tainted value.
            if !sanitizer_call_overlaps_tainted_call(sanitizer_match, context.tainted_call_spans)
                && !sanitizer_is_nested_in_tainted_sink_arg(sanitizer_match, &context.sink_tainted_args)
            {
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
    let from_test =
        crate::finding::path_is_test_file(&src.file) || crate::finding::path_is_test_file(&snk.file);

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
        chain_display: context.chain_names,
        taint_path: context.taint_path,
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
            let callee = rule.match_spec.callee.as_ref().and_then(|target| {
                target
                    .name
                    .clone()
                    .or_else(|| target.attribute.as_ref().map(|parts| parts.join(".")))
            })?;
            Some(CleanOutputOverwrite {
                callee,
                output_arg_index: semantics.output_arg_index,
                value_start_arg_index: semantics.value_start_arg_index,
            })
        })
        .collect()
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
            let callee = rule.match_spec.callee.as_ref().and_then(|target| {
                target
                    .name
                    .clone()
                    .or_else(|| target.attribute.as_ref().map(|parts| parts.join(".")))
            })?;
            Some(SourceOutputArgs {
                callee,
                output_arg_indices: semantics.source_output_args.clone(),
            })
        })
        .collect()
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
