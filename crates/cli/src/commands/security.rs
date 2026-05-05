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

#![allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]

use crate::args::{BrowseFormat, PrecisionFilter, SecurityAction};
use crate::commands::{
    emit_json_paged_cached, open_project_index_only, page_info_to_json, paging_from_cli, short_file,
};
use crate::footer::{render_paging_footer, render_truncation_notice};
use crate::page_cache;
use crate::paging;
use crate::ui::{extension_for, Ui};
use crate::{cli_println, progress, ui};
use anyhow::Result;
use bonsai_common::{FuncId, Precision};
use bonsai_sdk::{
    load_rulepack, load_workspace_local_rules, parse_severity, security_match_rows, tree_file_rel,
    CombinedFindingWithChain, CombinedSourceAnalysisCandidate, DependencyInventoryOptions, DependencyRow,
    Finding, FindingMatch, FindingStatus, PackInventoryOptions, PackRuleRow, Rule, RuleKind, RuleMatch,
    Rulepack, SecurityInventoryOptions, SecurityMatchRow, SecurityReport, Severity, SourceAnalysisOptions,
    TaintAnalysisOptions, TaintPropagationArg, TaintPropagationStep, TrustClass, CANONICAL_SINK_FAMILIES,
    FAMILY_NOT_APPLICABLE,
};
use comfy_table::Cell;
use indicatif::ProgressBar;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Open the workspace and attach the already-loaded rulepack so every
/// security subcommand sees the same rules without reloading.
fn open_security_project(
    workspace: &Path,
    pack: &Rulepack,
    rules_dir: &Path,
) -> Result<(bonsai_sdk::Project, crate::footer::WorkspaceFooter)> {
    let (project, footer) = open_project_index_only(workspace)?;
    Ok((project.with_loaded_rulepack(rules_dir, pack.clone()), footer))
}

/// Top-level dispatcher for `bonsai-ninja security <action>`. Loads the
/// rulepack once, merges any project-local overrides, then forwards
/// to the per-action handler.
pub(crate) fn cmd_security(workspace: &Path, action: SecurityAction) -> Result<()> {
    if page_cache::replay_if_hit(workspace)? {
        return Ok(());
    }

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
    let spin = progress::spinner("loading security rules");
    let mut pack = load_rulepack(&rules_dir)
        .map_err(|e| anyhow::anyhow!("security: rulepack load failed at `{}`: {e}", rules_dir.display()))?;
    if let Some(local) = load_workspace_local_rules(workspace)
        .map_err(|e| anyhow::anyhow!("security: project-local rule load failed: {e}"))?
    {
        let overridden = pack.merge_overriding(local);
        for id in overridden {
            eprintln!("warning: project-local rule `{id}` overrides global rule with the same id");
        }
    }
    spin.finish_and_clear();

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
            mut trust,
            category,
            sink,
            mut severity,
            tag,
            files,
            mut exclude_files,
            inferred_sources,
            exclude_tests,
            show_sanitized,
            taint_budget,
            intra_worklist_cap,
            precision,
            strict_flow,
            mut context,
            page,
            all,
            no_compact,
            format,
        } => {
            apply_profile(
                profile.as_deref(),
                &mut trust,
                &mut severity,
                &mut exclude_files,
                &mut context,
                /* set_severity = */ true,
            )?;
            let paging_cfg = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_flows(
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
                inferred_sources,
                exclude_tests,
                show_sanitized,
                taint_budget,
                intra_worklist_cap,
                precision,
                strict_flow,
                paging_cfg,
                no_compact,
                format,
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
            no_compact,
            format,
        } => {
            let mut ignored_severity: Option<String> = None;
            apply_profile(
                profile.as_deref(),
                &mut trust,
                &mut ignored_severity,
                &mut exclude_files,
                &mut context,
                /* set_severity = */ false,
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
                inferred_sources,
                paging_cfg,
                no_compact,
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
            context,
            page,
            all,
            limit,
            format,
        } => {
            let paging_cfg = paging_from_cli(context.as_deref(), page.as_deref(), all, format)?;
            cmd_pack(
                workspace, &pack, lang, category, kind, severity, audit, tree, validate, limit, paging_cfg,
                format,
            )
        }
    }
}

/// File-path filters excluded by `--profile production`. Mirrors the
/// SKILL.md "File Exclusion Defaults" set: common test, fixture,
/// sample, vendored dependency, build artifact, generated-code, and
/// language-specific non-production layouts.
///
/// Layered relationship with the workspace's index-time skip list
/// (`bonsai_workspace::SKIP_SEGMENTS`):
///   1. SKIP_SEGMENTS prevents files from being parsed/indexed at
///      all — vendored deps (`node_modules`, `target`, `vendor`,
///      `.git`) the user never wants to analyse.
///   2. PRODUCTION_EXCLUDES is a query-time filter on the indexed
///      workspace — keeps tests/fixtures/build-output INDEXED (so
///      `inspect`, `browse`, `flow` still see them) but drops them
///      from the security finding stream when this profile is
///      active. This is deliberate — security review wants
///      production code only, while `inspect` regularly needs to
///      walk into a test to see the harness setup.
///   3. The `--exclude-tests` flag is the third path-filter layer:
///      it drops findings whose source OR sink lives in a
///      `path_is_test_file` path (test-only subset of
///      PRODUCTION_EXCLUDES). Use it without `--profile production`
///      when you want the broader scan but no test-fixture noise.
///
/// Test-related entries below are kept in lockstep with
/// `bonsai_security::finding::path_is_test_file` so the two
/// classifications stay coherent.
const PRODUCTION_EXCLUDES: &[&str] = &[
    // Cross-language tests, fixtures, samples, and harnesses.
    "test/",
    "__tests__",
    "__mocks__",
    "tests/",
    "spec/",
    "specs/",
    "fixture/",
    "fixtures/",
    "mock/",
    "mocks/",
    "sample/",
    "samples/",
    "example/",
    "examples/",
    "demo/",
    "demos/",
    "e2e/",
    "integration/",
    "acceptance/",
    "_test.",
    ".test.",
    "_spec.",
    ".spec.",
    "_mock.",
    ".mock.",
    // JavaScript / TypeScript ecosystem.
    "node_modules/",
    "bower_components/",
    "coverage/",
    "cypress/",
    "playwright/",
    "storybook/",
    ".storybook/",
    ".next/",
    ".nuxt/",
    ".svelte-kit/",
    // Python ecosystem.
    "conftest.py",
    ".venv/",
    "venv/",
    "site-packages/",
    "_pb2.py",
    // JVM ecosystem.
    "src/test/",
    "src/it/",
    "Test.java",
    "Tests.java",
    "IT.java",
    "Test.kt",
    "Tests.kt",
    "IT.kt",
    "Test.scala",
    "Tests.scala",
    "IntegrationTest",
    // Go ecosystem.
    "_test.go",
    "testdata/",
    "Godeps/",
    // Ruby / PHP conventions.
    "_spec.rb",
    "_test.rb",
    "phpunit",
    // C# / .NET and Swift conventions.
    "Tests/",
    ".Tests",
    "UITests",
    "XCTest",
    "androidTest/",
    "bin/",
    "obj/",
    ".build/",
    // Rust, C, C++, and native build outputs.
    "target/",
    "benches/",
    "vendor/",
    "third_party/",
    "third-party/",
    "_deps/",
    "CMakeFiles/",
    "cmake-build",
    "Pods/",
    "Carthage/",
    // Generic build, generated, documentation, and deployment fixtures.
    "dist/",
    "build/",
    "out/",
    "generated/",
    "autogen/",
    ".gen.",
    "_gen.",
    "proto/gen/",
    "migrations/",
    "docs/",
    "doc/",
    "scripts/",
    "deploy/",
    "deployments/",
    "broadcast/",
    "cache/",
];

/// Apply a profile bundle to per-flag fields in-place. Per-flag values
/// already set by the user take precedence — the profile only fills
/// in defaults. Today only `production` is recognized; unknown
/// profile names are an error so typos surface immediately.
fn apply_profile(
    profile: Option<&str>,
    trust: &mut Option<String>,
    severity: &mut Option<String>,
    exclude_files: &mut Vec<String>,
    context: &mut Option<String>,
    set_severity: bool,
) -> Result<()> {
    let Some(name) = profile else {
        return Ok(());
    };
    match name {
        "production" => {
            if trust.is_none() {
                *trust = Some("remote".to_string());
            }
            if set_severity && severity.is_none() {
                *severity = Some("high".to_string());
            }
            if exclude_files.is_empty() {
                exclude_files.extend(PRODUCTION_EXCLUDES.iter().map(|s| (*s).to_string()));
            }
            if context.is_none() {
                *context = Some("16k".to_string());
            }
            Ok(())
        }
        other => Err(anyhow::anyhow!(
            "security: unknown --profile `{other}`; supported: production"
        )),
    }
}

/// Resolve the rulepack directory: explicit `--rules-dir` wins; otherwise
/// fall back to the SDK's centralised discovery, then the conventional
/// `security-patterns/` next to the workspace.
fn resolve_rules_dir(workspace: &Path, rules_dir: Option<&Path>) -> PathBuf {
    if let Some(d) = rules_dir {
        return d.to_path_buf();
    }
    bonsai_sdk::Bonsai::discover_rulepack_root(workspace)
        .unwrap_or_else(|| PathBuf::from("security-patterns"))
}

// ---- sources ----
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
    let (project, _footer) = open_security_project(workspace, pack, rules_dir)?;
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
    let matches = project.security().sources(options)?;
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

// ---- sinks ----
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
    let (project, _footer) = open_security_project(workspace, pack, rules_dir)?;
    let sev_floor = parse_severity_flag(severity.as_deref())?;
    let matches = project.security().sinks(SecurityInventoryOptions {
        rule: rule.clone(),
        rule_regex: rule_regex.clone(),
        severity: sev_floor,
        tag: tag.clone(),
        category: category.clone(),
        files: files.clone(),
        exclude_files: exclude_files.clone(),
        ..Default::default()
    })?;
    render_match_table(
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
    )
}

// ---- sanitizers ----
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
    let (project, _footer) = open_security_project(workspace, pack, rules_dir)?;
    let sev_floor = parse_severity_flag(severity.as_deref())?;
    let matches = project.security().sanitizers(SecurityInventoryOptions {
        rule: rule.clone(),
        rule_regex: rule_regex.clone(),
        tag: tag.clone(),
        severity: sev_floor,
        category: category.clone(),
        files: files.clone(),
        exclude_files: exclude_files.clone(),
        ..Default::default()
    })?;
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
    let (project, _footer) = open_security_project(workspace, pack, rules_dir)?;
    let inv = project.security().deps(DependencyInventoryOptions {
        framework: framework.clone(),
        severity: parse_severity_flag(severity.as_deref())?,
        files: files.clone(),
        exclude_files: exclude_files.clone(),
    })?;

    let filters_hash = filter_signature(&[
        ("kind", "deps"),
        ("framework", framework.as_deref().unwrap_or("")),
        ("severity", severity.as_deref().unwrap_or("")),
    ]);
    let cost = |r: &DependencyRow| {
        (r.language.len()
            + r.key.len()
            + r.rule_ids.iter().map(|s| s.len() + 1).sum::<usize>()
            + r.signals.iter().map(|s| s.len() + 1).sum::<usize>()
            + r.evidence_files.iter().map(|s| s.len() + 1).sum::<usize>()
            + 16) as u64
            + paging::TABLE_ROW_CHROME_BYTES
    };

    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
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
    trust: Option<String>,
    category: Option<String>,
    sink: Option<String>,
    severity: Option<String>,
    tag: Option<String>,
    files: Vec<String>,
    exclude_files: Vec<String>,
    inferred_sources: bool,
    exclude_tests: bool,
    show_sanitized: bool,
    taint_budget: Option<u32>,
    intra_worklist_cap: Option<u32>,
    precision: Option<PrecisionFilter>,
    strict_flow: bool,
    paging_cfg: paging::PagingConfig,
    no_compact: bool,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_security_project(workspace, pack, rules_dir)?;
    let ws = project.workspace();
    let sev_floor = parse_severity_flag(severity.as_deref())?;
    let max_precision = max_precision_from_cli(precision, strict_flow);
    let mut analysis_progress = SecurityAnalysisProgress::new();
    let report = project.security().taint_analysis_with_phase_progress(
        TaintAnalysisOptions {
            source: source.clone(),
            trust: trust.clone(),
            category: category.clone(),
            sink: sink.clone(),
            severity: sev_floor,
            tag: tag.clone(),
            files: files.clone(),
            exclude_files: exclude_files.clone(),
            include_inferred_sources: inferred_sources,
            show_sanitized,
            interprocedural_budget: taint_budget,
            intra_worklist_cap,
            max_precision,
            exclude_tests,
        },
        |event| analysis_progress.handle(event),
    )?;
    let (total_critical, total_high, total_medium) = report.severity_counts();
    let findings = report.findings;

    let filters_hash = filter_signature(&[
        ("kind", "taint-analysis"),
        ("source", source.as_deref().unwrap_or("")),
        ("trust", trust.as_deref().unwrap_or("")),
        ("category", category.as_deref().unwrap_or("")),
        ("sink", sink.as_deref().unwrap_or("")),
        ("severity", severity.as_deref().unwrap_or("")),
        ("tag", tag.as_deref().unwrap_or("")),
        ("show_sanitized", if show_sanitized { "1" } else { "0" }),
        (
            "taint_budget",
            &taint_budget.map(|v| v.to_string()).unwrap_or_default(),
        ),
        (
            "intra_worklist_cap",
            &intra_worklist_cap.map(|v| v.to_string()).unwrap_or_default(),
        ),
        (
            "precision",
            precision.map(precision_filter_label).unwrap_or_default(),
        ),
        ("strict_flow", if strict_flow { "1" } else { "0" }),
    ]);
    // Cheap header/JSON cost for JSON pagination. Text path uses a
    // render-accurate per-finding cost built below.
    let cost_finding_shallow = |f: &CombinedFindingWithChain| {
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
            + paging::TABLE_ROW_CHROME_BYTES
    };

    match format {
        BrowseFormat::Json => {
            emit_json_paged_cached(
                workspace,
                &findings,
                &paging_cfg,
                "security/taint-analysis",
                filters_hash,
                cost_finding_shallow,
            )?;
            return Ok(());
        }
        BrowseFormat::Sarif => {
            // SARIF 2.1.0 — direct serialization, no pagination.
            // Standardised SAST output expected by IDE integrations,
            // GitHub code scanning, and the CVEBench-SAST harness.
            // SARIF consumers expect the full result set in one
            // document; --all behavior is implicit.
            let plain: Vec<Finding> = findings.iter().map(|f| f.finding.clone()).collect();
            // Drain runtime-disabled rules collected by the matcher
            // (invalid regex, etc.) so the SARIF report surfaces them
            // alongside findings. Without this, rules silently
            // dropped at runtime would never reach the user.
            let report = SecurityReport::with_runtime_disabled_rules(
                plain,
                bonsai_sdk::drain_runtime_disabled_rules(),
            );
            let workspace_root = std::fs::canonicalize(workspace)
                .ok()
                .and_then(|path| path.to_str().map(str::to_owned))
                .unwrap_or_else(|| workspace.to_string_lossy().into_owned());
            cli_println!("{}", report.sarif_json_with_workspace_root(&workspace_root));
            return Ok(());
        }
        BrowseFormat::Text => {}
    }

    // Text path: `security taint-analysis` is a rulepack-driven
    // wrapper around `inspect`. Each finding gets a security header
    // (source rule, sanitizer rules, sink rule — with severity, CWE,
    // OWASP, category, packages, and the rule's description) followed
    // by an inspect-style FLOW block rendered from the finding's
    // chain, with full source bodies inlined. We call `inspect`'s own
    // `render_flow_with_filters` + `render_flow_block` helpers
    // directly so the body layout is byte-identical to
    // `bonsai-ninja inspect --query X`.
    // Paginate before rendering inspect-style FLOW bodies. Large
    // workspaces can produce thousands of findings; building every
    // rendered body just to show page 1 turns text mode into an
    // accidental full-report render. JSON `--all` remains the complete
    // machine-readable path.
    let indexed: Vec<usize> = (0..findings.len()).collect();
    let function_costs = function_costs_for_paths(
        ws,
        findings
            .iter()
            .flat_map(|finding| finding.chain_funcs.iter().copied()),
        true,
    );
    let cost_finding_text = |finding_index: &usize| {
        finding_text_cost_bytes(&findings[*finding_index], pack, &function_costs)
            + paging::TABLE_ROW_CHROME_BYTES
    };
    let (_current_idx, current_info) = paging::paginate(
        &indexed,
        &paging_cfg,
        "security/taint-analysis",
        filters_hash,
        cost_finding_text,
    );
    let total_pages = current_info.total_pages;
    let current_page = current_info.page_number;
    let mut cached_pages = Vec::new();
    for page_number in page_cache::eager_window(current_page, total_pages) {
        let mut page_cfg = paging_cfg.clone();
        page_cfg.page = paging::PageArg::Number(page_number);
        let (paged_idx, info) = paging::paginate(
            &indexed,
            &page_cfg,
            "security/taint-analysis",
            filters_hash,
            cost_finding_text,
        );
        let text = page_cache::capture(|| {
            render_taint_analysis_text_page(
                ws,
                pack,
                &findings,
                &paged_idx,
                &info,
                no_compact,
                total_critical,
                total_high,
                total_medium,
                report.source_rule_count,
                report.sink_rule_count,
                report.sanitizer_rule_count,
            )
        })?;
        cached_pages.push(page_cache::CachedPage {
            number: page_number,
            cursor: info.cursor,
            text,
        });
    }
    let _ = paging::paginate(
        &indexed,
        &paging_cfg,
        "security/taint-analysis",
        filters_hash,
        cost_finding_text,
    );
    if let Err(e) = page_cache::save_pages(workspace, cached_pages.clone()) {
        tracing::debug!("page cache save failed: {e}");
    }
    if let Some(page) = cached_pages.iter().find(|p| p.number == current_page) {
        page_cache::emit_cached_text(&page.text)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
fn render_taint_analysis_text_page(
    ws: &bonsai_sdk::Workspace,
    pack: &Rulepack,
    findings: &[CombinedFindingWithChain],
    paged_idx: &[usize],
    info: &paging::PageInfo,
    no_compact: bool,
    total_critical: usize,
    total_high: usize,
    total_medium: usize,
    source_rule_count: usize,
    sink_rule_count: usize,
    sanitizer_rule_count: usize,
) -> Result<()> {
    let u = ui();
    cli_println!(
        "{}",
        u.dim(&format!(
            "security taint-analysis — {} finding(s)  \
             (critical={}, high={}, medium={})  · \
             {} source rule(s) · {} sink rule(s) · {} sanitizer rule(s) loaded",
            findings.len(),
            total_critical,
            total_high,
            total_medium,
            source_rule_count,
            sink_rule_count,
            sanitizer_rule_count,
        ))
    );
    let paged_fc: Vec<&CombinedFindingWithChain> = paged_idx.iter().map(|i| &findings[*i]).collect();
    let paged_flows: Vec<Option<crate::commands::InspectFlowRendered>> = paged_idx
        .iter()
        .map(|i| {
            let fc = &findings[*i];
            if fc.chain_funcs.is_empty() {
                return None;
            }
            let filters = crate::commands::InspectFilters {
                from: None,
                from_kind: None,
                to: None,
                to_kind: None,
                file: None,
                in_fn: None,
            };
            let label = format!("{}", *i + 1);
            let mut flow = crate::commands::render_flow_with_filters(
                ws,
                &fc.chain_funcs,
                (*i + 1) as u32,
                &label,
                bonsai_common::Precision::Exact,
                None,
                filters,
            )?;
            if let Some(flow_id) = fc.finding.representative_flow_id.as_deref() {
                flow.flow_id = flow_id.to_string();
            }
            annotate_taint_flow(
                &mut flow,
                &fc.finding.source,
                &fc.additional_sources,
                &fc.finding.taint_path,
                Some(&fc.finding.sink),
            );
            Some(flow)
        })
        .collect();

    let render_opts = crate::commands::InspectRenderOptions {
        compact: false,
        flow_id_filter: None,
        view: crate::args::InspectView::Trace,
        group_id_filter: None,
    };
    let mut seen_bodies: crate::commands::BodySet = ahash::AHashSet::new();

    for (global_idx, (fc, prebuilt_flow)) in paged_idx.iter().zip(paged_fc.iter().zip(paged_flows.iter())) {
        render_finding_security_header(u, *global_idx + 1, fc, pack);
        match prebuilt_flow.as_ref() {
            Some(flow) => {
                let header_name = if fc.additional_sinks.is_empty() {
                    fc.finding.sink.rule_id.clone()
                } else {
                    format!(
                        "{} (+{} sink)",
                        fc.finding.sink.rule_id,
                        fc.additional_sinks.len()
                    )
                };
                if no_compact {
                    let mut local_seen: crate::commands::BodySet = ahash::AHashSet::new();
                    crate::commands::render_flow_block(u, &render_opts, flow, &header_name, &mut local_seen);
                } else {
                    crate::commands::render_flow_block(u, &render_opts, flow, &header_name, &mut seen_bodies);
                }
            }
            None => render_finding_block_compact(u, fc, pack, ws),
        }
    }

    render_paging_footer(info, "bonsai-ninja security <workspace> taint-analysis");
    Ok(())
}

// ---- source-analysis — downstream taint/call map from all source seeds ----
#[derive(Serialize, Clone)]
struct CombinedSourceAnalysisFlow {
    source: FindingMatch,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    additional_sources: Vec<FindingMatch>,
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
    inferred_sources: bool,
    paging_cfg: paging::PagingConfig,
    no_compact: bool,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = open_security_project(workspace, pack, rules_dir)?;
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
            include_inferred_sources: inferred_sources,
        },
        |event| analysis_progress.handle(event),
    )?;
    let source_rule_count = report.source_rule_count;
    let candidates = report.candidates;

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
        BrowseFormat::Json | BrowseFormat::Sarif => {
            if paging_cfg.json_wrapped() {
                page_cache::emit_paged_text(
                    workspace,
                    &candidates,
                    &paging_cfg,
                    "security/source-analysis",
                    filters_hash,
                    cost,
                    |paged, info, _cfg| {
                        let rendered = render_source_analysis_candidates(ws, paged);
                        let wrapped = serde_json::json!({
                            "rows": rendered,
                            "page": page_info_to_json(info),
                        });
                        cli_println!("{}", serde_json::to_string_pretty(&wrapped)?);
                        Ok(())
                    },
                )?;
            } else {
                let rendered = render_source_analysis_candidates(ws, &candidates);
                cli_println!("{}", serde_json::to_string_pretty(&rendered)?);
            }
            Ok(())
        }
        BrowseFormat::Text => {
            let function_costs =
                function_costs_for_paths(ws, candidates.iter().flat_map(|c| c.path.iter().copied()), true);
            let text_cost = |f: &CombinedSourceAnalysisCandidate| {
                source_analysis_text_cost_bytes(f, pack, &function_costs) + paging::TABLE_ROW_CHROME_BYTES
            };
            let (_current, current_info) = paging::paginate(
                &candidates,
                &paging_cfg,
                "security/source-analysis",
                filters_hash,
                text_cost,
            );
            let total_pages = current_info.total_pages;
            let current_page = current_info.page_number;
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
                );
                let text = page_cache::capture(|| {
                    render_source_analysis_text_page(
                        ws,
                        pack,
                        &paged,
                        &info,
                        no_compact,
                        candidates.len(),
                        source_rule_count,
                    )
                })?;
                cached_pages.push(page_cache::CachedPage {
                    number: page_number,
                    cursor: info.cursor,
                    text,
                });
            }
            let _ = paging::paginate(
                &candidates,
                &paging_cfg,
                "security/source-analysis",
                filters_hash,
                text_cost,
            );
            if let Err(e) = page_cache::save_pages(workspace, cached_pages.clone()) {
                tracing::debug!("page cache save failed: {e}");
            }
            if let Some(page) = cached_pages.iter().find(|p| p.number == current_page) {
                page_cache::emit_cached_text(&page.text)?;
            }
            Ok(())
        }
    }
}

fn render_source_analysis_text_page(
    ws: &bonsai_sdk::Workspace,
    pack: &Rulepack,
    candidates: &[CombinedSourceAnalysisCandidate],
    info: &paging::PageInfo,
    no_compact: bool,
    total_candidates: usize,
    source_rule_count: usize,
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
    let render_opts = crate::commands::InspectRenderOptions {
        compact: false,
        flow_id_filter: None,
        view: crate::args::InspectView::Trace,
        group_id_filter: None,
    };
    let mut seen_bodies: crate::commands::BodySet = ahash::AHashSet::new();
    for item in rendered.iter() {
        render_source_analysis_header(u, item.flow.flow_number as usize, item, pack);
        if no_compact {
            let mut local_seen: crate::commands::BodySet = ahash::AHashSet::new();
            crate::commands::render_flow_block(
                u,
                &render_opts,
                &item.flow,
                &item.source.rule_id,
                &mut local_seen,
            );
        } else {
            crate::commands::render_flow_block(
                u,
                &render_opts,
                &item.flow,
                &item.source.rule_id,
                &mut seen_bodies,
            );
        }
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
    let mut flow = crate::commands::render_flow_with_filters(
        ws,
        &item.path,
        (idx + 1) as u32,
        &label,
        bonsai_common::Precision::Exact,
        None,
        crate::commands::InspectFilters {
            from: Some(&item.source.text),
            from_kind: None,
            to: None,
            to_kind: None,
            file: None,
            in_fn: None,
        },
    )?;
    flow.flow_id.clone_from(&item.flow_id);
    annotate_taint_flow(
        &mut flow,
        &item.source,
        &item.additional_sources,
        &item.taint_path,
        None,
    );
    Some(CombinedSourceAnalysisFlow {
        source: item.source.clone(),
        additional_sources: item.additional_sources.clone(),
        flow,
    })
}

fn annotate_taint_flow(
    flow: &mut crate::commands::InspectFlowRendered,
    source: &FindingMatch,
    additional_sources: &[FindingMatch],
    taint_path: &[TaintPropagationStep],
    sink: Option<&FindingMatch>,
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
        add_flow_line_annotation(flow, &source.file, source.line, &label, marker, &mut step_counter);
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
        add_flow_line_annotation(flow, &step.file, step.line, &label, marker, &mut step_counter);
    }

    if let Some(sink) = sink {
        if !sink_annotated {
            let marker = format!("SINK: {} {}", sink.rule_id, format_sink_args(sink));
            add_flow_line_annotation(flow, &sink.file, sink.line, &label, marker, &mut step_counter);
        }
    }
}

fn add_flow_line_annotation(
    flow: &mut crate::commands::InspectFlowRendered,
    file: &str,
    line_no: u32,
    flow_label: &str,
    marker: String,
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
        let annotation = format!("[FLOW {flow_label} {marker}]");
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
        cli_println!("    {} {}", u.dim("summary:"), summary);
    }
}

/// Print the security-finding narrative for one finding. Framed as a
/// vulnerability report, not a raw rule dump: headline severity +
/// vulnerability class, a synthesised one-sentence summary of what's
/// happening, then labelled `SOURCE:` / `SANITIZER:` / `SINK:` blocks
/// that each read as short prose (what the input is, what the dangerous
/// operation is, why it's dangerous) plus the rule id, location, and
/// supporting taxonomy metadata (CWE, OWASP, category, packages,
/// frameworks). Goes above the inspect-style FLOW block so a reviewer
/// sees the finding *as a vulnerability* before reading the call chain.
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
        cli_println!("  {}   {}", u.dim("packages:"), u.dim(&packages.join(", ")));
    }
    let frameworks = combined_sink_metadata(combined, pack, |r| &r.frameworks);
    if !frameworks.is_empty() {
        cli_println!("  {} {}", u.dim("frameworks:"), u.dim(&frameworks.join(", ")));
    }
    cli_println!();

    // One-sentence synthesised summary. Pulls the source-rule
    // description (the "what the input is" half) and the sink-rule
    // description (the "why it's dangerous" half) from the YAML and
    // stitches them with "→". A plain-English overview before the
    // per-side evidence blocks below.
    if let Some(summary) = synth_summary(combined, pack) {
        cli_println!("  {} {}", u.dim("summary:"), summary);
        cli_println!();
    }

    render_finding_side(u, FindingSide::Source, &f.source, pack);
    for source in &combined.additional_sources {
        render_finding_side(u, FindingSide::Source, source, pack);
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
    Sanitizer,
    Sink,
}

impl FindingSide {
    fn label(self) -> &'static str {
        match self {
            Self::Source => "SOURCE:",
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
            Self::Sanitizer => "sanitized via —",
            Self::Sink => "dangerous operation —",
        }
    }
}

/// Emit one side of the finding (source / sanitizer / sink) as a
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
            cli_println!("    {} {}", u.dim(side.narrative_prefix()), u.dim(desc),);
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
        cli_println!("    {} {}", u.dim("tainted args:"), u.dim(&args_text));
    }
    // Supporting taxonomy chips — only fields not already in the
    // finding headline above, so we don't repeat severity / cwe /
    // owasp / packages / frameworks for the sink side.
    let mut chips: Vec<String> = Vec::new();
    if matches!(side, FindingSide::Source) {
        if let Some(trust) = m.trust.as_deref() {
            chips.push(format!("{}={}", u.dim("trust"), u.dim(trust)));
        }
    }
    if let Some(tag) = m.tag.as_deref() {
        chips.push(format!("{}={}", u.dim("tag"), u.dim(tag)));
    }
    if let Some(cat) = m.category.as_deref() {
        chips.push(format!("{}={}", u.dim("category"), u.dim(cat)));
    }
    // Sink-side only: sink severity (source severity is irrelevant).
    // The finding's severity (from the sink) already appears in the
    // headline, so skip it here.
    if matches!(side, FindingSide::Sanitizer) {
        if let Some(r) = rule {
            if !r.packages.is_empty() {
                chips.push(format!("{}={}", u.dim("packages"), u.dim(&r.packages.join(","))));
            }
        }
    }
    if !chips.is_empty() {
        cli_println!("    {}  [{}]", u.dim("—"), chips.join(" · "));
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

/// Fallback render when the finding has no resolved FuncId chain —
/// a compact SOURCE / SANITIZER / SINK block list with the
/// syntax-highlighted code line at each site, no source bodies.
/// Same visual shape as the per-side blocks in the taint-analysis
/// render, so same-file findings (which can't produce a cross-function
/// chain) still read coherently.
fn render_finding_block_compact(
    u: &Ui,
    combined: &CombinedFindingWithChain,
    pack: &Rulepack,
    ws: &bonsai_sdk::Workspace,
) {
    let f = &combined.finding;
    cli_println!();
    cli_println!("{}", u.dim("(no cross-function chain — same-file fallback)"));
    render_site_code(u, "SOURCE", &f.source, pack, ws);
    for source in &combined.additional_sources {
        render_site_code(u, "SOURCE", source, pack, ws);
    }
    for s in &f.sanitizers_seen {
        render_site_code(u, "SANITIZER", s, pack, ws);
    }
    render_site_code(u, "SINK", &f.sink, pack, ws);
    for sink in &combined.additional_sinks {
        render_site_code(u, "SINK", sink, pack, ws);
    }
}

fn render_site_code(u: &Ui, label: &str, m: &FindingMatch, pack: &Rulepack, ws: &bonsai_sdk::Workspace) {
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
    let code = read_line(ws, &m.file, m.line);
    if !code.trim().is_empty() {
        cli_println!("    {}", u.snippet(code.trim(), extension_for(&m.file)));
    }
    if let Some(r) = pack.find_rule_by_id(&m.rule_id) {
        let desc = r.description.trim();
        if !desc.is_empty() {
            cli_println!("    {}", u.dim(desc));
        }
    }
}

fn read_line(ws: &bonsai_sdk::Workspace, file_path: &str, line: u32) -> String {
    crate::commands::browse::read_line(ws, file_path, line)
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
    let global = ws.db().global_index();
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

fn finding_text_cost_bytes(
    finding: &CombinedFindingWithChain,
    pack: &Rulepack,
    function_costs: &ahash::AHashMap<FuncId, u64>,
) -> u64 {
    let mut cost = 1600
        + finding.finding.finding_id.len() as u64
        + finding
            .finding
            .cwe
            .iter()
            .map(|c| c.len() as u64 + 2)
            .sum::<u64>()
        + finding
            .finding
            .owasp
            .iter()
            .map(|o| o.len() as u64 + 2)
            .sum::<u64>()
        + finding
            .finding
            .chain_display
            .iter()
            .map(|hop| hop.len() as u64 + 8)
            .sum::<u64>();
    cost += match_text_cost(&finding.finding.source, pack);
    cost += match_text_cost(&finding.finding.sink, pack);
    cost += finding
        .additional_sources
        .iter()
        .map(|m| match_text_cost(m, pack))
        .sum::<u64>();
    cost += finding
        .additional_sinks
        .iter()
        .map(|m| match_text_cost(m, pack))
        .sum::<u64>();
    cost += finding
        .finding
        .sanitizers_seen
        .iter()
        .map(|m| match_text_cost(m, pack))
        .sum::<u64>();
    if finding.chain_funcs.is_empty() {
        return cost + 1024;
    }
    cost + 700
        + finding
            .chain_funcs
            .iter()
            .map(|func| function_costs.get(func).copied().unwrap_or(512))
            .sum::<u64>()
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

// ---- shared helpers ----
/// Renders one progress bar per `AnalysisProgress` phase emitted by the
/// security analysis pipeline. Each `PhaseStarted` opens a fresh bar
/// with the announced total, `PhaseTicked` increments it, and
/// `PhaseFinished` clears it. `Drop` is the safety net for early
/// returns / errors that bypass the explicit `PhaseFinished`.
struct SecurityAnalysisProgress {
    bar: Option<ProgressBar>,
}

impl SecurityAnalysisProgress {
    fn new() -> Self {
        Self { bar: None }
    }

    fn handle(&mut self, event: bonsai_sdk::AnalysisProgress) {
        match event {
            bonsai_sdk::AnalysisProgress::PhaseStarted { label, total } => {
                if let Some(bar) = self.bar.take() {
                    bar.finish_and_clear();
                }
                self.bar = Some(if total == 0 {
                    progress::spinner(label)
                } else {
                    progress::progress_bar(label, total)
                });
            }
            bonsai_sdk::AnalysisProgress::PhaseTicked => {
                if let Some(bar) = &self.bar {
                    bar.inc(1);
                }
            }
            bonsai_sdk::AnalysisProgress::PhaseFinished => {
                if let Some(bar) = self.bar.take() {
                    bar.finish_and_clear();
                }
            }
        }
    }
}

impl Drop for SecurityAnalysisProgress {
    fn drop(&mut self) {
        if let Some(bar) = self.bar.take() {
            bar.finish_and_clear();
        }
    }
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

fn max_precision_from_cli(precision: Option<PrecisionFilter>, strict_flow: bool) -> Option<Precision> {
    precision
        .map(precision_filter_to_common)
        .or_else(|| strict_flow.then_some(Precision::Narrowed))
}

fn precision_filter_to_common(precision: PrecisionFilter) -> Precision {
    match precision {
        PrecisionFilter::Exact => Precision::Exact,
        PrecisionFilter::Narrowed => Precision::Narrowed,
        PrecisionFilter::OverApproximate => Precision::OverApproximate,
        PrecisionFilter::Unknown => Precision::Unknown,
    }
}

fn precision_filter_label(precision: PrecisionFilter) -> &'static str {
    match precision {
        PrecisionFilter::Exact => "exact",
        PrecisionFilter::Narrowed => "narrowed",
        PrecisionFilter::OverApproximate => "over-approximate",
        PrecisionFilter::Unknown => "unknown",
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

// ---- match-table renderer (sources + sinks) ----
/// Render `security sources` / `security sinks` matches as one inspect-
/// style block per match — rule id + metadata chips, file:line:col +
/// enclosing fn, syntax-highlighted source line, rule description.
/// Replaces the old dense table so triaging a hit doesn't require
/// opening the YAML. JSON output keeps every field (including the new
/// description / cwe / owasp / frameworks / packages chips) so tooling
/// gets the same context.
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
        BrowseFormat::Json | BrowseFormat::Sarif => {
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
                    let payload = serde_json::json!({
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
        chips.push(format!("{}={}", u.dim("severity"), severity_cell(u, sev)));
    }
    if let Some(trust) = rule.and_then(|r| r.trust) {
        chips.push(format!("{}={}", u.dim("trust"), u.dim(trust_str(trust))));
    }
    if let Some(cat) = rule.and_then(|r| r.category.as_deref()) {
        chips.push(format!("{}={}", u.dim("category"), u.dim(cat)));
    }
    if let Some(tag) = rule.and_then(|r| r.tag.as_deref()) {
        chips.push(format!("{}={}", u.dim("tag"), u.dim(tag)));
    }
    if let Some(r) = rule {
        if !r.cwe.is_empty() {
            chips.push(format!("{}={}", u.dim("cwe"), u.dim(&r.cwe.join(","))));
        }
        if !r.frameworks.is_empty() {
            chips.push(format!(
                "{}={}",
                u.dim("frameworks"),
                u.dim(&r.frameworks.join(","))
            ));
        }
        if !r.packages.is_empty() {
            chips.push(format!("{}={}", u.dim("packages"), u.dim(&r.packages.join(","))));
        }
    }
    let chip_trailer = if chips.is_empty() {
        String::new()
    } else {
        format!("  [{}]", chips.join(" · "))
    };
    cli_println!();
    cli_println!(
        "{}  {}{}",
        u.kind(&format!("[{label} {idx}]")),
        u.name(&m.rule_id),
        chip_trailer,
    );
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
            cli_println!("    {}", u.dim(desc));
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
        chips.push(format!(
            "{}={}",
            u.dim("severity"),
            severity_cell(u, sev.as_str())
        ));
    }
    chips.push(format!("{}={}", u.dim("lang"), u.dim(&r.language)));
    if !r.tags.is_empty() {
        chips.push(format!("{}={}", u.dim("tags"), u.dim(&r.tags.join(","))));
    }
    chips.push(format!(
        "{}={}",
        u.dim("rules"),
        u.dim(&format!("{}", r.rule_ids.len()))
    ));
    if !r.signals.is_empty() {
        let take: Vec<&str> = r.signals.iter().take(4).map(|s| s.as_str()).collect();
        let mut joined = take.join(",");
        if r.signals.len() > 4 {
            joined.push_str(&format!(",+{} more", r.signals.len() - 4));
        }
        chips.push(format!("{}={}", u.dim("signals"), u.dim(&joined)));
    }
    let chip_trailer = format!("  [{}]", chips.join(" · "));
    cli_println!();
    cli_println!(
        "{}  {}{}",
        u.kind(&format!("[PACKAGE {idx}]")),
        u.name(&r.key),
        chip_trailer,
    );

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
                cli_println!("    {} {}", u.dim("·"), u.dim(desc));
            }
        }
    }
}

// ---- pack — rulepack inspector / auditor ----
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
    limit: usize,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let kind_filter = match kind.as_deref() {
        Some("source") => Some(RuleKind::Source),
        Some("sink") => Some(RuleKind::Sink),
        Some("sanitizer") => Some(RuleKind::Sanitizer),
        Some(other) => anyhow::bail!("unknown --kind `{other}` (expected source|sink|sanitizer)"),
        None => None,
    };
    let sev_floor = parse_severity_flag(severity.as_deref())?;

    let pack_facade = bonsai_sdk::SecurityPack::new(pack);
    let pack_options = PackInventoryOptions {
        lang: lang.clone(),
        category: category.clone(),
        kind: kind_filter,
        severity: sev_floor,
    };

    if audit {
        return render_audit(pack, lang.as_deref(), format);
    }
    if validate {
        return render_pack_validation(pack, &pack_options, format);
    }
    if tree {
        // Use the SDK's `select_pack_rules` to filter+sort once
        // instead of an O(rows × pack.all_rules) membership scan.
        // Don't run `inventory()` first — the tree branch never
        // touches `rows`.
        let rules = pack_facade.select_rules(&pack_options);
        return render_tree(pack, &rules, pack_options, format);
    }
    // Single source of truth for filter/sort on the non-tree
    // branch: the SDK's `inventory()` filters by
    // lang/kind/severity/category and sorts by
    // `(lang, kind, family, id)`. Both text and JSON render paths
    // consume the same `Vec<PackRuleRow>` so they can never drift
    // on filter semantics.
    let rows = pack_facade.inventory(pack_options.clone())?;

    let filters_hash = filter_signature(&[
        ("kind", "pack"),
        ("lang", lang.as_deref().unwrap_or("")),
        ("category", category.as_deref().unwrap_or("")),
        ("rkind", kind.as_deref().unwrap_or("")),
        ("severity", severity.as_deref().unwrap_or("")),
    ]);

    let cost_row = |r: &PackRuleRow| {
        (r.rule_id.len() + r.language.len() + r.tag.as_deref().map_or(0, str::len) + r.description.len() + 32)
            as u64
            + paging::TABLE_ROW_CHROME_BYTES
    };
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            page_cache::emit_paged_text(
                workspace,
                &rows,
                &paging_cfg,
                "security/pack",
                filters_hash,
                cost_row,
                |paged, info, _cfg| {
                    let payload = serde_json::json!({
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
                    let headers = [
                        "rule",
                        "lang",
                        "kind",
                        "family",
                        "tag",
                        "severity",
                        "on?",
                        "description",
                    ];
                    let mut t = u.table(&headers);
                    for r in &display_rows {
                        let sev = r.severity.as_deref().unwrap_or("-");
                        let tag = r.tag.as_deref().unwrap_or("-");
                        let on = if r.enabled { "y" } else { "·" };
                        t.add_row(vec![
                            Cell::new(u.name(&r.rule_id)),
                            Cell::new(u.dim(&r.language)),
                            Cell::new(u.kind(&r.kind)),
                            Cell::new(u.kind(&r.family)),
                            Cell::new(u.dim(tag)),
                            Cell::new(severity_cell(u, sev)),
                            Cell::new(u.dim(on)),
                            Cell::new(u.dim(&r.description)),
                        ]);
                    }
                    cli_println!("{t}");
                    cli_println!("{}", u.dim(&format!("({row_count} rule(s))")));
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
    pack: &Rulepack,
    options: &PackInventoryOptions,
    format: BrowseFormat,
) -> Result<()> {
    let report = bonsai_sdk::SecurityPack::new(pack).validate(options.clone())?;
    match format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            cli_println!("{}", serde_json::to_string_pretty(&report)?);
        }
        BrowseFormat::Text => {
            let u = ui();
            let status = if report.valid {
                u.name("valid")
            } else {
                u.warn("invalid")
            };
            cli_println!(
                "security pack validation — {} ({} rule(s), {} enabled, {} disabled, {} waiting on re-enable work, {} example(s) on enabled rules / {} total, {} error(s), {} warning(s))",
                status,
                report.rule_count,
                report.enabled_rule_count,
                report.disabled_rule_count,
                report.disabled_waiting_reenable_count,
                report.enabled_example_count,
                report.example_count,
                report.errors,
                report.warnings
            );
            if !report.disabled_reason_counts.is_empty() {
                let counts = report
                    .disabled_reason_counts
                    .iter()
                    .map(|(code, count)| format!("{code}: {count}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                cli_println!("{}", u.dim(&format!("disabled reasons — {counts}")));
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

fn render_audit(pack: &Rulepack, lang_filter: Option<&str>, format: BrowseFormat) -> Result<()> {
    // Single source of truth: the SDK's `pack_audit` builds the
    // per-(lang, family) matrix and applies the canonical
    // family-normalisation. CLI text rendering walks the same
    // report so JSON and text never disagree.
    let report = bonsai_sdk::SecurityPack::new(pack).audit(lang_filter)?;

    if matches!(format, BrowseFormat::Json) {
        cli_println!("{}", serde_json::to_string_pretty(&report)?);
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
    for fam in CANONICAL_SINK_FAMILIES {
        headers.push(family_short_label(fam));
    }
    headers.push("gaps");
    let mut t = u.table(&headers);
    t.set_content_arrangement(comfy_table::ContentArrangement::Disabled);
    let ecosystem_specific: Vec<&str> = report
        .languages
        .iter()
        .filter(|l| !l.canonical_sink_families_applicable)
        .map(|l| l.language.as_str())
        .collect();
    for lang in &report.languages {
        let mut row: Vec<Cell> = vec![
            Cell::new(u.name(&lang.language)),
            Cell::new(count_cell(u, lang.sources.enabled, 5)),
            Cell::new(count_cell(u, lang.sanitizers.enabled, 5)),
        ];
        if !lang.canonical_sink_families_applicable {
            for _ in CANONICAL_SINK_FAMILIES {
                row.push(Cell::new(u.dim("n/a")));
            }
            row.push(Cell::new(u.dim("n/a")));
            t.add_row(row);
            continue;
        }
        let mut gaps: Vec<&str> = Vec::new();
        for fam in CANONICAL_SINK_FAMILIES {
            let entry = lang.sinks.get(*fam);
            let not_applicable = entry.is_some_and(|e| e.not_applicable);
            if not_applicable {
                row.push(Cell::new(u.dim("n/a")));
                continue;
            }
            let enabled = entry.map_or(0, |e| e.enabled);
            row.push(Cell::new(count_cell(u, enabled, 3)));
            if enabled == 0 {
                gaps.push(*fam);
            }
        }
        let gap_str = if gaps.is_empty() {
            "-".to_string()
        } else {
            // Short form in the gaps cell too so it doesn't force the
            // row to balloon past the terminal width.
            let shorts: Vec<&str> = gaps.iter().map(|f| family_short_label(f)).collect();
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
    if !ecosystem_specific.is_empty() {
        cli_println!(
            "{}",
            u.dim(&format!(
                "n/a = canonical web-family audit does not apply to ecosystem-specific languages ({})",
                ecosystem_specific.join(", ")
            ))
        );
    }
    if !FAMILY_NOT_APPLICABLE.is_empty() {
        let descriptions: Vec<String> = FAMILY_NOT_APPLICABLE
            .iter()
            .map(|(lang, fam)| format!("{lang}/{}", family_short_label(fam)))
            .collect();
        cli_println!(
            "{}",
            u.dim(&format!(
                "n/a (per-cell) = family intentionally empty for this lang ({})",
                descriptions.join(", ")
            ))
        );
    }
    cli_println!(
        "{}",
        u.dim(&format!(
            "covered: {} language(s); canonical sink families tracked: {}",
            report.languages.len(),
            CANONICAL_SINK_FAMILIES.len()
        ))
    );
    // Legend — print every abbreviation ↔ full family name so the
    // column headers are self-documenting.
    let legend = CANONICAL_SINK_FAMILIES
        .iter()
        .map(|fam| {
            let short = family_short_label(fam);
            if short == *fam {
                (*fam).to_string()
            } else {
                format!("{short}={fam}")
            }
        })
        .collect::<Vec<_>>()
        .join("  ");
    cli_println!("{}", u.dim(&format!("legend: {legend}")));
    Ok(())
}

/// Compact column label for the audit matrix. Keep a stable 3-5 char
/// abbreviation for each long family name so 21-language × 17-family
/// tables don't force comfy-table into char-wrapping mode. Families
/// whose natural name is already short (`xss`, `jwt`, `tls`, …) are
/// returned verbatim.
fn family_short_label(fam: &str) -> &'static str {
    match fam {
        "cmdi" => "cmdi",
        "sqli" => "sqli",
        "nosql" => "nosq",
        "path" => "path",
        "ssrf" => "ssrf",
        "xss" => "xss",
        "eval" => "eval",
        "deserialization" => "dser",
        "xxe" => "xxe",
        "ldap" => "ldap",
        "jwt" => "jwt",
        "crypto" => "cryp",
        "tls" => "tls",
        "template" => "tmpl",
        "open_redirect" => "oredr",
        "file_upload" => "upld",
        "header_injection" => "hdr",
        // Unknown family — return a stable placeholder rather than
        // leaking a fresh `Box::leak(String)` on every call. The
        // CANONICAL list is closed today; if it grows, add an arm
        // above so the column shows the real abbreviation.
        _ => "?",
    }
}

/// Pattern tree: rules grouped by (lang, kind, family) with headers
/// that mirror the actual YAML files on disk. Shows enabled/disabled counts per file
/// plus each rule's id, severity, and enabled state — a quick
/// file-level pack survey. Respects `--lang` / `--kind` /
/// `--category` / `--severity` via the already-filtered `rules` slice.
fn render_tree(
    pack: &Rulepack,
    rules: &[&Rule],
    _options: PackInventoryOptions,
    format: BrowseFormat,
) -> Result<()> {
    if matches!(format, BrowseFormat::Json) {
        // Pass the prebuilt rule slice through `pack_tree_for_rules`
        // so we don't re-run the same filter+sort that produced
        // `rules` in the first place. The SDK helper that takes
        // `PackInventoryOptions` would internally re-derive the
        // same `rules` slice — wasted work.
        let report = bonsai_sdk::SecurityPack::new(pack).tree_for_rules(rules)?;
        cli_println!("{}", serde_json::to_string_pretty(&report)?);
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
    }
}

// Rule family normalisation lives behind the SDK/security facade so
// JSON and text pack renderers share one canonical mapping.
