//! `bonsai_security` — rulepack-driven security wrapper around
//! `bonsai_inspect`.
//!
//! The crate implements the spec in `docs/security-spec.mdx`:
//!
//! * YAML rulepack loader, one per supported language.
//! * Rule → `inspect`-flag compiler (no second query language).
//! * Source / sink / sanitizer matchers over browse facts.
//! * Finding builder with stable `S:` ids + taint / edge / flow
//!   drill-down ids.
//! * Dependency inventory from rule metadata + workspace imports.
//! * Render adapters for grouped / compact / graph / train JSON.
//!
//! The CLI (`bonsai_cli::commands::security`) is a thin front for
//! the types and functions re-exported here.

// External API is the re-exports below. Tests under `tests/`
// legitimately use `bonsai_security::loader::LanguagePack` and
// `bonsai_security::rule::TrustClass`, so those two stay `pub`. The
// remaining submodules are internal — consumers go through the
// re-exports.
pub(crate) mod analysis;
pub(crate) mod compile;
pub(crate) mod deps;
pub(crate) mod finding;
pub mod flow_evidence;
pub mod loader;
pub(crate) mod matcher;
pub(crate) mod pkg;
pub(crate) mod report;
pub mod rule;
pub(crate) mod sanitizer_credit;

pub use analysis::{
    canonical_sink_audit_applies, dependency_inventory, filter_rules_to_workspace_languages,
    normalise_family, pack_audit, pack_inventory, pack_tree, pack_tree_for_rules, rule_family,
    run_source_analysis, run_source_analysis_with_phase_progress, run_source_analysis_with_progress,
    run_taint_analysis, run_taint_analysis_with_phase_progress, run_taint_analysis_with_progress,
    sanitizer_inventory, sanitizer_inventory_with_progress, security_match_rows, security_model_for_lang,
    seed_idg_service_for_rulepack, select_pack_rules, select_rules, sink_inventory,
    sink_inventory_with_progress, source_inventory, source_inventory_with_progress,
    source_rule_matches_filters, taint_transfers_from_rulepack, tree_file_rel, validate_pack,
    workspace_languages, AnalysisProgress, CombinedFindingWithChain, CombinedSourceAnalysisCandidate,
    DependencyInventoryOptions, FindingWithChain, PackAuditCount, PackAuditFamilyCount, PackAuditLanguage,
    PackAuditReport, PackInventoryOptions, PackRuleRow, PackTreeFile, PackTreeLanguage, PackTreeReport,
    PackTreeRule, PackValidationIssue, PackValidationReport, RulepackTaintTransfers,
    SecurityInventoryOptions, SecurityMatchRow, SourceAnalysisCandidate, SourceAnalysisOptions,
    SourceAnalysisReport, SourceLineageLimits, SourceLineageStatus, SourceLineageSummary,
    TaintAnalysisOptions, TaintAnalysisReport, CANONICAL_SINK_FAMILIES, ECOSYSTEM_SPECIFIC_SINK_AUDIT_LANGS,
    FAMILY_NOT_APPLICABLE,
};
pub use compile::{compile_rule_to_inspect_args, CompiledRule};
pub use deps::{build_inventory, DependencyInventory, DependencyRow};
pub use finding::{
    compute_finding_id, AlternateTaintFlow, Finding, FindingMatch, FindingStatus, TaintFlowRef,
    TaintPropagationArg, TaintPropagationStep, TaintedArgInfo,
};
pub use flow_evidence::{build_flow_bodies, FlowFunctionBody, FlowRole, FlowSourceLine};
pub use loader::{load_rulepack, load_workspace_local_rules, parse_severity, LoadError, Rulepack};
pub use matcher::{
    drain_runtime_disabled_rules, infer_entry_point_sources, match_rule_against_facts,
    match_rules_against_facts, match_rules_against_facts_with_progress, InterTaintView, RuleMatch,
    RuntimeDisabledRule, MATCHER_POLICY_FINGERPRINT,
};
pub use report::{
    render_deps_text, render_graph_json, render_grouped_text, render_sarif_json, render_train_json,
    SecurityReport,
};
pub use rule::{
    AnalysisSemantics, ArgTaintedSpec, ConfiguredArgumentFactoryGuardSemantics, ConstraintKind,
    ContextFlowRole, ContextFlowSemantics, FlowClass, GuardProfile, MatchKind, MatchOrigin, MatchSpec,
    MustAliasSpec, NoSqlFilterSemantics, ParameterizedQuerySemantics, PathConsumerContainmentGuardSemantics,
    PathContainmentGuardSemantics, PayloadType, PostSinkPolicy, RelativePathContainmentGuardSemantics,
    RequiredNamedArgumentSemantics, RequiresStateSpec, Rule, RuleConstraint, RuleKind, RuleTarget,
    RuntimeTypeSpec, Severity, TrustClass, UrlComponentSemantics, UrlDnsGuardSemantics,
    UrlGuardRootSemantics, UrlHostAllowlistSemantics, UrlNetworkGuardSemantics, UrlRedirectGuardSemantics,
    UrlSchemeGuardSemantics,
};
pub use sanitizer_credit::{sanitizer_credits_sink_tag, sanitizer_tag_is_recognized_non_crediting};
