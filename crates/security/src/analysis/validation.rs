//! Rulepack validation.
//!
//! `validate_pack` and its per-rule validators check a loaded rulepack for
//! metadata, taint-semantics, regex, and package-signal problems, emitting
//! [`PackValidationIssue`]s. Split out of `analysis::mod` to keep the
//! analysis driver focused. Relies on the parent module for the shared rule /
//! matcher / workspace types and the `run_taint_analysis` / `select_pack_rules`
//! helpers it drives.

#[allow(clippy::wildcard_imports)]
use super::*;

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
        let taint_dependent = rule_has_taint_dependent_constraint(rule);
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
                let mut has_package_signal = false;
                for file_id in ws.db().global_index().all_files() {
                    let Some(import_index) = ws.db().import_index(file_id) else {
                        if let Some(idx) = ws.db().decl_index(file_id) {
                            if decl_index_has_java_like_fqn_package_signal(&rule.language, &idx, &signals) {
                                has_package_signal = true;
                                break;
                            }
                        }
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
                        has_package_signal = true;
                        break;
                    }
                    if let Some(idx) = ws.db().decl_index(file_id) {
                        if decl_index_has_java_like_fqn_package_signal(&rule.language, &idx, &signals) {
                            has_package_signal = true;
                            break;
                        }
                    }
                }
                if !has_package_signal {
                    push_validation_issue(
                        &mut issues,
                        "warning",
                        "match-example-missing-import",
                        Some(rule),
                        &format!(
                            "example `{}` does not import or fully qualify any of {:?} — the rule's \
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
            // Taint-dependent examples require source-to-sink dataflow,
            // not just static owner matching. Running full taint analysis
            // for every rulepack example makes `pack --validate` scale
            // with thousands of tiny whole-pack scans, so by default the
            // owner-miss path below treats these examples as not statically
            // checkable and taint behavior is covered by rulepack
            // conformance and security pipeline fixtures. When
            // `taint_replay_examples` is set (the deep CI gate), replay them
            // through live taint instead — `match_example_owner_texts`
            // routes taint-dependent sinks through `run_taint_analysis` — so
            // a rule whose own positive example silently stopped firing is
            // caught rather than shipped.
            let replay_taint = options.taint_replay_examples;
            let skip_taint_example = taint_dependent && !replay_taint;
            let match_texts = if skip_taint_example {
                Vec::new()
            } else {
                match_example_owner_texts(pack, rule, &ws)
            };
            if example.expect_no_match {
                if skip_taint_example {
                    continue;
                }
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
                // them. Unless we're replaying through taint (above),
                // skip them here so the validator and the
                // `declared_rule_match_examples_fire` test agree on which
                // examples are statically checkable.
                if skip_taint_example {
                    continue;
                }
                // A taint-dependent example that produced no finding under
                // live replay gets its own code so the deep gate can be
                // tracked separately from the static owner-miss path.
                let (code, detail) = if taint_dependent {
                    (
                        "match-example-taint-miss",
                        "produced no taint finding for its owner rule under example replay",
                    )
                } else {
                    ("match-example-owner-miss", "produced no match for its owner rule")
                };
                push_validation_issue(
                    &mut issues,
                    "warning",
                    code,
                    Some(rule),
                    &format!(
                        "example `{}` {detail}",
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
            if rule.enabled && !taint_dependent {
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
        if !taint_dependent {
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
            show_sanitized: true,
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

fn decl_index_has_java_like_fqn_package_signal(
    language: &str,
    idx: &bonsai_lang_api::DeclIndex,
    signals: &[&str],
) -> bool {
    if !matches!(language, "java" | "kotlin" | "scala") {
        return false;
    }
    idx.refs.iter().any(|reference| {
        matches!(
            reference.kind,
            bonsai_lang_api::RefKind::Call | bonsai_lang_api::RefKind::Type
        ) && crate::pkg::java_like_fully_qualified_package(&reference.name).is_some_and(|package| {
            signals
                .iter()
                .any(|signal| crate::pkg::import_matches_package(package, signal))
        })
    })
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
            // Typing rules carry no tag/severity/trust/cwe. They provide a
            // factory return type and/or an external library transfer summary.
            RuleKind::Typing => {
                if rule.returns_type.is_none() && rule.taint_semantics.is_none() {
                    push_validation_issue(
                        issues,
                        "error",
                        "missing-returns-type",
                        Some(rule),
                        "enabled typing rule must declare returns_type or taint_semantics",
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
        if !matches!(rule.kind, RuleKind::Sink | RuleKind::Typing) {
            push_validation_issue(
                issues,
                "error",
                "invalid-taint-semantics",
                Some(rule),
                "taint_semantics.taint_receiver_from_args is only valid on sink or typing rules",
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
    if !semantics.source_callback_args.is_empty() && rule.kind != RuleKind::Source {
        push_validation_issue(
            issues,
            "error",
            "invalid-taint-semantics",
            Some(rule),
            "taint_semantics.source_callback_args is only valid on source rules",
        );
    }
    for callback in &semantics.source_callback_args {
        if callback.source_param_indices.is_empty() {
            push_validation_issue(
                issues,
                "error",
                "invalid-taint-semantics",
                Some(rule),
                "taint_semantics.source_callback_args entries require source_param_indices",
            );
        }
    }
    if !semantics.call_result_passthrough_args.is_empty()
        && !matches!(rule.kind, RuleKind::Sanitizer | RuleKind::Typing)
    {
        push_validation_issue(
            issues,
            "error",
            "invalid-taint-semantics",
            Some(rule),
            "taint_semantics.call_result_passthrough_args is only valid on sanitizer or typing rules",
        );
    }
    if semantics.call_result_passthrough_receiver
        && !matches!(rule.kind, RuleKind::Sanitizer | RuleKind::Typing)
    {
        push_validation_issue(
            issues,
            "error",
            "invalid-taint-semantics",
            Some(rule),
            "taint_semantics.call_result_passthrough_receiver is only valid on sanitizer or typing rules",
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
            | crate::rule::ConstraintKind::ReceiverTypeNotIn { .. }
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
            | crate::rule::ConstraintKind::SinkTagIn { .. }
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
pub(super) fn package_signal_distro_smell(language: &str, signal: &str) -> Option<&'static str> {
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
                "pyyaml",              // → yaml
                "beautifulsoup4",      // → bs4
                "djangorestframework", // → rest_framework
                "pillow",              // → PIL
                "msgpack-python",      // pre-2.0; → msgpack (also has `-`)
                "python3-saml",        // → onelogin.saml2
                "pycryptodome",        // → Crypto (top-level shim)
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

pub(super) fn lowercase_receiver_token_from_regex(regex: &str) -> Option<String> {
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
pub(super) fn regex_prefix_is_receiver_agnostic(regex: &str) -> bool {
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
