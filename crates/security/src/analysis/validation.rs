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
    let rulepack_typing = crate::matcher::build_rulepack_typing(&pack.all_rules());
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
    validate_rulepack_metadata(pack, &mut issues);

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
            // Tree-sitter import-index check (no source-text heuristic).
            // Package/module-gated rules need at least one adapter-visible
            // import or fully-qualified type use in positive examples.
            if !example.expect_no_match && !signals.is_empty() {
                let mut has_package_signal = false;
                for file_id in ws.db().vfs().all_files() {
                    let Some(import_index) = ws.db().import_index(file_id) else {
                        continue;
                    };
                    for spec in &import_index.imports {
                        example_imports.insert(spec.module.clone());
                    }
                    if import_index.imports.iter().any(|spec| {
                        signals.iter().any(|sig| {
                            crate::pkg::import_matches_package(&spec.module, sig, &rule.package_matching)
                        })
                    }) {
                        has_package_signal = true;
                        break;
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
                             package gate cannot fire on this example",
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
                match_example_owner_texts(pack, rule, &ws, &rulepack_typing)
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
        validate_package_signals_match_example_imports(pack, rule, &example_imports, &mut issues);
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
        for hit in
            crate::matcher::match_rules_against_facts_with_factory(&prepared.ws, &peers, &rulepack_typing)
        {
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

fn match_example_owner_texts(
    pack: &Rulepack,
    rule: &Rule,
    ws: &Workspace,
    factory: &Arc<crate::matcher::RulepackTyping>,
) -> Vec<String> {
    if rule.kind == RuleKind::Sink && rule_has_taint_dependent_constraint(rule) {
        return match_arg_tainted_example_owner_texts(pack, rule, ws);
    }
    crate::matcher::match_rule_against_facts_with_factory(ws, rule, factory)
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
                | ConstraintKind::ReceiverOriginCallbackParamReachesCall { .. }
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

fn validate_package_signals_match_example_imports(
    pack: &Rulepack,
    rule: &Rule,
    example_imports: &BTreeSet<String>,
    issues: &mut Vec<PackValidationIssue>,
) {
    let has_signal = !rule.packages.is_empty() || !rule.imports.is_empty() || !rule.modules.is_empty();
    if !rule.enabled || !has_signal || example_imports.is_empty() {
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
    let aliases = pack
        .metadata
        .languages
        .get(&rule.language)
        .map(|metadata| &metadata.package_aliases);
    if signals.iter().any(|signal| {
        example_imports.iter().any(|imported| {
            crate::pkg::import_matches_package(imported, signal, &rule.package_matching)
                || aliases
                    .and_then(|aliases| aliases.get(&signal.to_ascii_lowercase()))
                    .is_some_and(|aliases| {
                        aliases.iter().any(|alias| {
                            crate::pkg::import_matches_package(imported, alias, &rule.package_matching)
                        })
                    })
        })
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

fn validate_rulepack_metadata(pack: &Rulepack, issues: &mut Vec<PackValidationIssue>) {
    let all_rules = pack.all_rules();
    let sink_tags: BTreeSet<&str> = all_rules
        .iter()
        .filter(|rule| rule.kind == RuleKind::Sink)
        .filter_map(|rule| rule.tag.as_deref())
        .collect();
    let sanitizer_tags: BTreeSet<&str> = all_rules
        .iter()
        .filter(|rule| rule.kind == RuleKind::Sanitizer)
        .filter_map(|rule| rule.tag.as_deref())
        .collect();

    let canonical_families = pack
        .metadata
        .canonical_sink_families
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for family in &canonical_families {
        let valid = pack
            .metadata
            .sink_family_short_labels
            .get(*family)
            .is_some_and(|label| !label.trim().is_empty() && label.chars().count() <= 5);
        if !valid {
            push_validation_issue(
                issues,
                "error",
                "missing-sink-family-short-label",
                None,
                &format!(
                    "metadata canonical sink family `{family}` needs a nonempty sink_family_short_labels value of at most five characters"
                ),
            );
        }
    }
    for family in pack.metadata.sink_family_short_labels.keys() {
        if !canonical_families.contains(family.as_str()) {
            push_validation_issue(
                issues,
                "error",
                "unknown-sink-family-short-label",
                None,
                &format!("metadata sink_family_short_labels key `{family}` is not a canonical sink family"),
            );
        }
    }

    for (sanitizer_tag, credited_sink_tags) in &pack.metadata.sanitizer_credits {
        if !sanitizer_tags.contains(sanitizer_tag.as_str()) {
            push_validation_issue(
                issues,
                "error",
                "unknown-sanitizer-credit-tag",
                None,
                &format!("metadata sanitizer_credits key `{sanitizer_tag}` is not used by a sanitizer rule"),
            );
        }
        for sink_tag in credited_sink_tags {
            if !sink_tags.contains(sink_tag.as_str()) {
                push_validation_issue(
                    issues,
                    "error",
                    "unknown-sanitizer-credit-sink-tag",
                    None,
                    &format!(
                        "metadata sanitizer_credits.{sanitizer_tag} targets unknown sink tag `{sink_tag}`"
                    ),
                );
            }
        }
    }
    for tag in pack.metadata.sink_tag_semantics.keys() {
        if !sink_tags.contains(tag.as_str()) {
            push_validation_issue(
                issues,
                "error",
                "unknown-sink-tag-semantics",
                None,
                &format!("metadata sink_tag_semantics key `{tag}` is not used by a sink rule"),
            );
        }
    }
    for tag in pack.metadata.sanitizer_tag_semantics.keys() {
        if !sanitizer_tags.contains(tag.as_str()) {
            push_validation_issue(
                issues,
                "error",
                "unknown-sanitizer-tag-semantics",
                None,
                &format!("metadata sanitizer_tag_semantics key `{tag}` is not used by a sanitizer rule"),
            );
        }
    }

    for (name, profile) in &pack.metadata.profiles {
        if name.trim().is_empty() {
            push_validation_issue(
                issues,
                "error",
                "invalid-profile-name",
                None,
                "metadata profile names must not be empty",
            );
        }
        if profile
            .context
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
            || profile.exclude_paths.iter().any(|value| value.trim().is_empty())
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-profile-value",
                None,
                &format!("metadata profile `{name}` contains an empty context or path pattern"),
            );
        }
    }
    if pack
        .metadata
        .test_path_patterns
        .iter()
        .any(|pattern| pattern.trim().is_empty())
    {
        push_validation_issue(
            issues,
            "error",
            "invalid-test-path-pattern",
            None,
            "metadata test_path_patterns must not contain empty values",
        );
    }
    for (language, metadata) in &pack.metadata.languages {
        let package = &metadata.package_matching;
        let contains_empty = package
            .strip_import_prefixes
            .iter()
            .chain(package.strip_import_suffixes.iter())
            .chain(package.package_separators.iter())
            .any(|value| value.is_empty());
        let invalid_tail = package
            .call_qualifier_from_package_tail
            .as_ref()
            .is_some_and(|binding| {
                binding.package_separator.is_empty()
                    || binding.call_separators.is_empty()
                    || binding.call_separators.iter().any(String::is_empty)
            });
        if contains_empty || invalid_tail {
            push_validation_issue(
                issues,
                "error",
                "invalid-package-matching-semantics",
                None,
                &format!(
                    "metadata language `{language}` package_matching values and tail-binding separators must be non-empty"
                ),
            );
        }
    }
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
    if rule.kind != RuleKind::Typing
        && (rule.match_spec.kind == MatchKind::Type
            || !rule.callback_param_types.is_empty()
            || rule.callback_arg_index.is_some())
    {
        push_validation_issue(
            issues,
            "error",
            "typing-fields-outside-typing-rule",
            Some(rule),
            "match.kind type, callback_param_types, and callback_arg_index are valid only in typing rules",
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
            // factory return type, callback parameter types, an external
            // library transfer summary, and/or a lifecycle transition.
            RuleKind::Typing => {
                if rule.returns_type.is_none()
                    && rule.callback_param_types.is_empty()
                    && rule.taint_semantics.is_none()
                    && rule.lifecycle_transition.is_none()
                {
                    push_validation_issue(
                        issues,
                        "error",
                        "missing-typing-semantics",
                        Some(rule),
                        "enabled typing rule must declare returns_type, callback_param_types, taint_semantics, or lifecycle_transition",
                    );
                }
                if !rule.callback_param_types.is_empty() {
                    let invalid_shape = rule.callback_param_types.iter().any(Vec::is_empty)
                        || match rule.match_spec.kind {
                            MatchKind::Call => rule.callback_arg_index.is_none(),
                            MatchKind::Type => rule.callback_arg_index.is_some(),
                            _ => true,
                        };
                    if invalid_shape {
                        push_validation_issue(
                            issues,
                            "error",
                            "invalid-callback-param-types",
                            Some(rule),
                            "callback_param_types requires match.kind call plus callback_arg_index, or match.kind type without callback_arg_index; every parameter needs at least one type alias",
                        );
                    }
                } else if rule.callback_arg_index.is_some() {
                    push_validation_issue(
                        issues,
                        "error",
                        "orphan-callback-arg-index",
                        Some(rule),
                        "callback_arg_index requires callback_param_types",
                    );
                }
            }
        }
    }
    validate_rule_regexes(rule, issues);
    validate_no_hardcoded_receiver_regex(rule, issues);
    validate_receiver_agnostic_regex_has_package_gate(rule, issues);
    validate_analysis_semantics(rule, issues);
    validate_callback_origin_constraints(rule, issues);
    validate_taint_semantics(rule, issues);
    validate_yaml_language_field(rule, issues);
}

fn validate_callback_origin_constraints(rule: &Rule, issues: &mut Vec<PackValidationIssue>) {
    let callable_target = |target: &RuleTarget| {
        target.name.as_ref().is_some_and(|name| !name.trim().is_empty())
            || target
                .attribute
                .as_ref()
                .is_some_and(|parts| !parts.is_empty() && parts.iter().all(|part| !part.trim().is_empty()))
            || target
                .regex
                .as_ref()
                .is_some_and(|pattern| !pattern.trim().is_empty())
    };
    for constraint in &rule.constraints.0 {
        let ConstraintKind::ReceiverOriginCallbackParamReachesCall {
            receiver_origin_callback_param_reaches_call: spec,
        } = constraint
        else {
            continue;
        };
        if rule.kind != RuleKind::Sink || !matches!(rule.match_spec.kind, MatchKind::Call | MatchKind::Write)
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-callback-origin-constraint",
                Some(rule),
                "receiver_origin_callback_param_reaches_call is valid only on sink rules with match.kind=call or match.kind=write",
            );
        }
        if !callable_target(&spec.receiver_factory)
            || !callable_target(&spec.receiver_member)
            || !callable_target(&spec.callback_call)
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-callback-origin-constraint",
                Some(rule),
                "receiver_origin_callback_param_reaches_call requires callable receiver_factory, receiver_member, and callback_call targets",
            );
        }
        for (role, target) in [
            ("receiver_factory", &spec.receiver_factory),
            ("receiver_member", &spec.receiver_member),
            ("callback_call", &spec.callback_call),
        ] {
            if let Some(pattern) = target.regex.as_deref() {
                if let Err(error) = Regex::new(pattern) {
                    push_validation_issue(
                        issues,
                        "error",
                        "invalid-callback-origin-constraint",
                        Some(rule),
                        &format!(
                            "receiver_origin_callback_param_reaches_call.{role}.regex is invalid: {error}"
                        ),
                    );
                }
            }
        }
    }
    for constraint in &rule.constraints.0 {
        let ConstraintKind::ReceiverFactoryArgumentFieldsEqual {
            receiver_factory_argument_fields_equal: spec,
        } = constraint
        else {
            continue;
        };
        if rule.kind != RuleKind::Sink || rule.match_spec.kind != MatchKind::Call {
            push_validation_issue(
                issues,
                "error",
                "invalid-receiver-factory-fields-constraint",
                Some(rule),
                "receiver_factory_argument_fields_equal is valid only on sink rules with match.kind=call",
            );
        }
        let has_invalid_fields = spec.required_fields.is_empty()
            || spec
                .required_fields
                .iter()
                .any(|field| field.path.is_empty() || field.path.iter().any(|part| part.trim().is_empty()))
            || spec.required_fields.iter().enumerate().any(|(index, field)| {
                spec.required_fields[index + 1..]
                    .iter()
                    .any(|other| other.path == field.path)
            });
        if !callable_target(&spec.factory) || has_invalid_fields {
            push_validation_issue(
                issues,
                "error",
                "invalid-receiver-factory-fields-constraint",
                Some(rule),
                "receiver_factory_argument_fields_equal requires a callable factory and unique non-empty exact field paths",
            );
        }
        if let Some(pattern) = spec.factory.regex.as_deref() {
            if let Err(error) = Regex::new(pattern) {
                push_validation_issue(
                    issues,
                    "error",
                    "invalid-receiver-factory-fields-constraint",
                    Some(rule),
                    &format!("receiver_factory_argument_fields_equal.factory.regex is invalid: {error}"),
                );
            }
        }
    }
    for constraint in &rule.constraints.0 {
        let ConstraintKind::UnlessPriorReceiverCall {
            unless_prior_receiver_call: spec,
        } = constraint
        else {
            continue;
        };
        if rule.kind != RuleKind::Sink || rule.match_spec.kind != MatchKind::Call {
            push_validation_issue(
                issues,
                "error",
                "invalid-prior-receiver-call-constraint",
                Some(rule),
                "unless_prior_receiver_call is valid only on sink rules with match.kind=call",
            );
        }
        if !callable_target(&spec.call) {
            push_validation_issue(
                issues,
                "error",
                "invalid-prior-receiver-call-constraint",
                Some(rule),
                "unless_prior_receiver_call requires a non-empty callable target",
            );
        }
        if let Some(pattern) = spec.call.regex.as_deref() {
            if let Err(error) = Regex::new(pattern) {
                push_validation_issue(
                    issues,
                    "error",
                    "invalid-prior-receiver-call-constraint",
                    Some(rule),
                    &format!("unless_prior_receiver_call.call.regex is invalid: {error}"),
                );
            }
        }
    }
}

fn validate_analysis_semantics(rule: &Rule, issues: &mut Vec<PackValidationIssue>) {
    let Some(semantics) = rule.analysis_semantics.as_ref() else {
        return;
    };
    for class in &semantics.flow_classes {
        let valid_kind = match class {
            FlowClass::ProcessInput | FlowClass::HttpInput | FlowClass::EnvironmentInput => {
                rule.kind == RuleKind::Source
            }
            FlowClass::ProcessExecution | FlowClass::BrowserOutput => rule.kind == RuleKind::Sink,
        };
        if !valid_kind {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "analysis_semantics.flow_classes contains a class incompatible with the rule kind",
            );
        }
    }
    if (semantics.source_specificity_rank.is_some() || semantics.source_reporting_rank.is_some())
        && rule.kind != RuleKind::Source
    {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "analysis_semantics source ranks are only valid on source rules",
        );
    }
    if (semantics.suppress_inferred_sources.is_some()
        || !semantics.suppress_local_source_flow_classes.is_empty())
        && rule.kind != RuleKind::Sink
    {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "source-suppression reporting policy is only valid on sink rules",
        );
    }
    if (semantics.guard_profile.is_some()
        || semantics.sink_terminal_priority.is_some()
        || semantics.path_containment_guard.is_some()
        || semantics.path_consumer_containment_guard.is_some()
        || semantics.relative_path_containment_guard.is_some()
        || semantics.parameterized_query.is_some()
        || semantics.nosql_filter.is_some()
        || semantics.dynamic_key_denylist_guard.is_some()
        || semantics.receiver_factory_guard.is_some()
        || semantics.receiver_configuration_guard.is_some()
        || semantics.configured_argument_factory_guard.is_some()
        || semantics.configured_argument_receiver_guard.is_some()
        || semantics.configured_call_argument_guard.is_some()
        || semantics.character_escape.is_some()
        || semantics.character_constraint.is_some()
        || semantics.same_origin_path_constraint.is_some()
        || semantics.url_network_guard.is_some()
        || semantics.url_reconstruction_guard.is_some()
        || semantics.context_flow.is_some()
        || semantics.post_sink_policy.is_some()
        || semantics.sanitizer_attachment_policy.is_some()
        || !semantics.receiver_factory_lineage_builders.is_empty())
        && rule.kind != RuleKind::Sink
    {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "sink and sanitizer-attachment analysis semantics are only valid on sink rules",
        );
    }
    if semantics.sanitizer_guard.is_some() && rule.kind != RuleKind::Sanitizer {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "sanitizer_guard is only valid on sanitizer rules",
        );
    }
    if semantics.sanitizer_attachment_policy == Some(SanitizerAttachmentPolicy::ReceiverFactoryLineage)
        && semantics.receiver_factory_lineage_builders.is_empty()
    {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "receiver-factory-lineage requires at least one rulepack-owned receiver_factory_lineage_builders target",
        );
    }
    for (index, target) in semantics.receiver_factory_lineage_builders.iter().enumerate() {
        if target.is_empty() {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                &format!("receiver_factory_lineage_builders[{index}] must be a non-empty callable target"),
            );
        }
        if let Some(pattern) = target.regex.as_deref() {
            if let Err(error) = Regex::new(pattern) {
                push_validation_issue(
                    issues,
                    "error",
                    "invalid-analysis-semantics",
                    Some(rule),
                    &format!("receiver_factory_lineage_builders[{index}].regex is invalid: {error}"),
                );
            }
        }
    }
    if semantics.sanitizer_guard.as_ref().is_some_and(|guard| {
        let role_count = usize::from(guard.use_receiver)
            + usize::from(guard.all_arguments)
            + usize::from(!guard.argument_indices.is_empty());
        role_count != 1
    }) {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "sanitizer_guard must select exactly one of receiver, all arguments, or argument indices",
        );
    }
    if let Some(guard) = semantics.configured_call_argument_guard.as_ref() {
        let invalid = guard.guarded_value_argument_indices.is_empty()
            || guard.required_fields.is_empty()
            || guard
                .required_fields
                .iter()
                .any(|field| field.path.is_empty() || field.path.iter().any(|part| part.trim().is_empty()));
        if invalid {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "configured_call_argument_guard requires guarded value indices and non-empty exact field paths",
            );
        }
    }
    if semantics.character_constraint.as_ref().is_some_and(|guard| {
        (guard.required_excluded_characters.is_empty() && guard.required_mappings.is_empty())
            || guard
                .required_excluded_characters
                .iter()
                .any(|character| character.chars().count() != 1)
            || guard
                .required_mappings
                .iter()
                .any(|mapping| mapping.input.chars().count() != 1 || mapping.output.is_empty())
            || {
                let mut inputs = std::collections::HashSet::new();
                !guard
                    .required_mappings
                    .iter()
                    .all(|mapping| inputs.insert(mapping.input.as_str()))
            }
            || guard
                .required_enclosing_literal_delimiter
                .as_ref()
                .is_some_and(|delimiter| delimiter.chars().count() != 1)
    }) {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "character_constraint requires single-character exclusions and/or unique exact non-empty substitutions and, when present, a single-character enclosing delimiter",
        );
    }
    if semantics
        .same_origin_path_constraint
        .as_ref()
        .is_some_and(|guard| {
            !guard.require_scheme_rejection
                && !guard.require_authority_rejection
                && !guard.require_absolute_path
                && !guard.require_scheme_relative_rejection
        })
    {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "same_origin_path_constraint must require at least one proven boundary",
        );
    }
    if semantics
        .same_origin_path_constraint
        .as_ref()
        .and_then(|guard| guard.static_context_argument.as_ref())
        .is_some_and(|context| {
            context.accepted_renderings.is_empty()
                || context
                    .accepted_renderings
                    .iter()
                    .any(|rendering| rendering.trim().is_empty())
        })
    {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "same_origin_path_constraint static_context_argument requires non-empty exact renderings",
        );
    }
    let path_profile = semantics.guard_profile == Some(GuardProfile::CanonicalPathContainment);
    if path_profile != semantics.path_containment_guard.is_some() {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "python-path-containment guard_profile and path_containment_guard must be declared together",
        );
    }
    let path_consumer_profile = semantics.guard_profile == Some(GuardProfile::PathConsumerContainment);
    if path_consumer_profile != semantics.path_consumer_containment_guard.is_some() {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "path-consumer-containment guard_profile and path_consumer_containment_guard must be declared together",
        );
    }
    let relative_path_profile = semantics.guard_profile == Some(GuardProfile::RelativePathContainment);
    if relative_path_profile != semantics.relative_path_containment_guard.is_some() {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "relative-path-containment guard_profile and relative_path_containment_guard must be declared together",
        );
    }
    if let Some(path_guard) = semantics.path_containment_guard.as_ref() {
        let callable_target = |target: &RuleTarget| {
            target.name.as_ref().is_some_and(|name| !name.trim().is_empty())
                || target.attribute.as_ref().is_some_and(|parts| {
                    !parts.is_empty() && parts.iter().all(|part| !part.trim().is_empty())
                })
                || target
                    .regex
                    .as_ref()
                    .is_some_and(|regex| !regex.trim().is_empty())
        };
        if !callable_target(&path_guard.canonicalizer)
            || !callable_target(&path_guard.containment_check)
            || path_guard.boundary_places.is_empty()
            || path_guard
                .boundary_places
                .iter()
                .any(|place| place.trim().is_empty())
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "path_containment_guard requires callable canonicalizer/containment_check targets and non-empty boundary_places",
            );
        }
        for (role, target) in [
            ("canonicalizer", &path_guard.canonicalizer),
            ("containment_check", &path_guard.containment_check),
        ] {
            if let Some(pattern) = target.regex.as_deref() {
                if let Err(error) = Regex::new(pattern) {
                    push_validation_issue(
                        issues,
                        "error",
                        "invalid-analysis-semantics",
                        Some(rule),
                        &format!("path_containment_guard.{role}.regex is invalid: {error}"),
                    );
                }
            }
        }
    }
    if let Some(path_guard) = semantics.path_consumer_containment_guard.as_ref() {
        let callable_target = |target: &RuleTarget| {
            target.name.as_ref().is_some_and(|name| !name.trim().is_empty())
                || target.attribute.as_ref().is_some_and(|parts| {
                    !parts.is_empty() && parts.iter().all(|part| !part.trim().is_empty())
                })
                || target
                    .regex
                    .as_ref()
                    .is_some_and(|regex| !regex.trim().is_empty())
        };
        if !callable_target(&path_guard.canonicalizer)
            || path_guard
                .base_canonicalizer
                .as_ref()
                .is_some_and(|target| !callable_target(target))
            || !callable_target(&path_guard.path_constructor)
            || !callable_target(&path_guard.containment_check)
            || path_guard
                .static_base_factories
                .iter()
                .any(|target| !callable_target(target))
            || (!path_guard.containment_check_is_segment_aware && path_guard.boundary_places.is_empty())
            || path_guard
                .boundary_places
                .iter()
                .any(|place| place.trim().is_empty())
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "path_consumer_containment_guard requires callable canonicalizer/path_constructor/containment_check targets and either segment-aware containment or non-empty boundary_places",
            );
        }
        for (role, target) in [
            ("canonicalizer", &path_guard.canonicalizer),
            (
                "base_canonicalizer",
                path_guard
                    .base_canonicalizer
                    .as_ref()
                    .unwrap_or(&path_guard.canonicalizer),
            ),
            ("path_constructor", &path_guard.path_constructor),
            ("containment_check", &path_guard.containment_check),
        ] {
            if let Some(pattern) = target.regex.as_deref() {
                if let Err(error) = Regex::new(pattern) {
                    push_validation_issue(
                        issues,
                        "error",
                        "invalid-analysis-semantics",
                        Some(rule),
                        &format!("path_consumer_containment_guard.{role}.regex is invalid: {error}"),
                    );
                }
            }
        }
    }
    if let Some(path_guard) = semantics.relative_path_containment_guard.as_ref() {
        let callable_target = |target: &RuleTarget| {
            target.name.as_ref().is_some_and(|name| !name.trim().is_empty())
                || target.attribute.as_ref().is_some_and(|parts| {
                    !parts.is_empty() && parts.iter().all(|part| !part.trim().is_empty())
                })
                || target
                    .regex
                    .as_ref()
                    .is_some_and(|regex| !regex.trim().is_empty())
        };
        if !callable_target(&path_guard.candidate_canonicalizer)
            || !callable_target(&path_guard.base_canonicalizer)
            || !callable_target(&path_guard.relative_path)
            || !callable_target(&path_guard.rejection_check)
            || path_guard.relative_base_arg_index == path_guard.relative_candidate_arg_index
            || path_guard.rejected_exact_values.is_empty()
            || path_guard
                .rejected_exact_values
                .iter()
                .any(|value| value.is_empty())
            || path_guard.rejection_prefix_arg_index.is_some()
                && (path_guard.rejection_boundary_places.is_empty()
                    || path_guard.rejection_boundary_wrappers.is_empty()
                    || path_guard
                        .rejection_boundary_places
                        .iter()
                        .any(|place| place.trim().is_empty())
                    || path_guard
                        .rejection_boundary_wrappers
                        .iter()
                        .any(|target| !callable_target(target)))
            || path_guard.rejection_prefix_arg_index.is_none()
                && (!path_guard.rejection_boundary_places.is_empty()
                    || !path_guard.rejection_boundary_wrappers.is_empty())
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "relative_path_containment_guard requires callable targets, distinct relative-path base/candidate arguments, and non-empty rejected_exact_values",
            );
        }
        for (role, target) in [
            ("candidate_canonicalizer", &path_guard.candidate_canonicalizer),
            ("base_canonicalizer", &path_guard.base_canonicalizer),
            ("relative_path", &path_guard.relative_path),
            ("rejection_check", &path_guard.rejection_check),
        ]
        .into_iter()
        .chain(
            path_guard
                .rejection_boundary_wrappers
                .iter()
                .map(|target| ("rejection_boundary_wrappers", target)),
        ) {
            if let Some(pattern) = target.regex.as_deref() {
                if let Err(error) = Regex::new(pattern) {
                    push_validation_issue(
                        issues,
                        "error",
                        "invalid-analysis-semantics",
                        Some(rule),
                        &format!("relative_path_containment_guard.{role}.regex is invalid: {error}"),
                    );
                }
            }
        }
    }
    if semantics
        .parameterized_query
        .as_ref()
        .is_some_and(|query| query.query_arg_index == query.bindings_arg_index)
    {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "parameterized_query requires distinct query_arg_index and bindings_arg_index values",
        );
    }
    if semantics.nosql_filter.as_ref().is_some_and(|filter| {
        filter.literal_value_operators.is_empty()
            || filter
                .literal_value_operators
                .iter()
                .any(|operator| operator.trim().is_empty())
            || filter
                .safe_scalar_compiler_types
                .iter()
                .any(|type_name| type_name.trim().is_empty())
            || filter
                .safe_scalar_source_rules
                .iter()
                .any(|rule_id| rule_id.trim().is_empty())
    }) {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "nosql_filter requires non-empty literal operators, compiler types, and source-rule ids",
        );
    }
    if let Some(guard) = semantics.dynamic_key_denylist_guard.as_ref() {
        let callable_target = |target: &RuleTarget| {
            target.name.as_ref().is_some_and(|name| !name.trim().is_empty())
                || target.attribute.as_ref().is_some_and(|parts| {
                    !parts.is_empty() && parts.iter().all(|part| !part.trim().is_empty())
                })
                || target
                    .regex
                    .as_ref()
                    .is_some_and(|regex| !regex.trim().is_empty())
        };
        if !callable_target(&guard.collection_constructor)
            || !callable_target(&guard.membership_check)
            || guard.rejected_exact_values.is_empty()
            || guard.rejected_exact_values.iter().any(String::is_empty)
            || (guard.require_recursive_filter && guard.filtered_value_argument_index.is_none())
            || (!guard.require_recursive_filter && guard.filtered_value_argument_index.is_some())
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "dynamic_key_denylist_guard requires callable constructor/membership targets, non-empty rejected_exact_values, and a filtered_value_argument_index exactly when recursive filtering is required",
            );
        }
        for (role, target) in [
            ("collection_constructor", &guard.collection_constructor),
            ("membership_check", &guard.membership_check),
        ] {
            if let Some(pattern) = target.regex.as_deref() {
                if let Err(error) = Regex::new(pattern) {
                    push_validation_issue(
                        issues,
                        "error",
                        "invalid-analysis-semantics",
                        Some(rule),
                        &format!("dynamic_key_denylist_guard.{role}.regex is invalid: {error}"),
                    );
                }
            }
        }
    }
    if let Some(guard) = semantics.receiver_factory_guard.as_ref() {
        let callable_target = |target: &RuleTarget| {
            target.name.as_ref().is_some_and(|name| !name.trim().is_empty())
                || target.attribute.as_ref().is_some_and(|parts| {
                    !parts.is_empty() && parts.iter().all(|part| !part.trim().is_empty())
                })
                || target
                    .regex
                    .as_ref()
                    .is_some_and(|regex| !regex.trim().is_empty())
        };
        if guard.factories.is_empty()
            || guard.factories.iter().any(|target| !callable_target(target))
            || guard
                .required_nested_factories
                .iter()
                .any(|target| !callable_target(target))
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "receiver_factory_guard requires at least one callable factory target",
            );
        }
        for (role, targets) in [
            ("factories", guard.factories.as_slice()),
            (
                "required_nested_factories",
                guard.required_nested_factories.as_slice(),
            ),
        ] {
            for (index, target) in targets.iter().enumerate() {
                if let Some(pattern) = target.regex.as_deref() {
                    if let Err(error) = Regex::new(pattern) {
                        push_validation_issue(
                            issues,
                            "error",
                            "invalid-analysis-semantics",
                            Some(rule),
                            &format!("receiver_factory_guard.{role}[{index}].regex is invalid: {error}"),
                        );
                    }
                }
            }
        }
    }
    if let Some(guard) = semantics.receiver_configuration_guard.as_ref() {
        let callable_target = |target: &RuleTarget| {
            target.name.as_ref().is_some_and(|name| !name.trim().is_empty())
                || target.attribute.as_ref().is_some_and(|parts| {
                    !parts.is_empty() && parts.iter().all(|part| !part.trim().is_empty())
                })
                || target
                    .regex
                    .as_ref()
                    .is_some_and(|regex| !regex.trim().is_empty())
        };
        let invalid = guard.required_calls.is_empty()
            || guard.required_calls.iter().any(|required| {
                !callable_target(&required.call)
                    || {
                        let identity: AHashSet<_> =
                            required.identity_argument_indices.iter().copied().collect();
                        identity.len() != required.identity_argument_indices.len()
                            || identity.iter().any(|index| {
                                !required
                                    .required_arguments
                                    .iter()
                                    .any(|argument| argument.index == *index)
                            })
                    }
                    || required.required_arguments.iter().any(|argument| {
                        (!argument.require_static_value
                            && argument.accepted_places.is_empty()
                            && argument.accepted_static_values.is_empty())
                            || argument
                                .accepted_places
                                .iter()
                                .any(|place| place.trim().is_empty())
                    })
            });
        if invalid {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "receiver_configuration_guard requires callable required_calls and non-empty exact argument places",
            );
        }
        for (index, required) in guard.required_calls.iter().enumerate() {
            if let Some(pattern) = required.call.regex.as_deref() {
                if let Err(error) = Regex::new(pattern) {
                    push_validation_issue(
                        issues,
                        "error",
                        "invalid-analysis-semantics",
                        Some(rule),
                        &format!(
                            "receiver_configuration_guard.required_calls[{index}].call.regex is invalid: {error}"
                        ),
                    );
                }
            }
        }
    }
    if let Some(guard) = semantics.configured_argument_factory_guard.as_ref() {
        let callable_target = |target: &RuleTarget| {
            target.name.as_ref().is_some_and(|name| !name.trim().is_empty())
                || target.attribute.as_ref().is_some_and(|parts| {
                    !parts.is_empty() && parts.iter().all(|part| !part.trim().is_empty())
                })
                || target
                    .regex
                    .as_ref()
                    .is_some_and(|regex| !regex.trim().is_empty())
        };
        let mut names = BTreeSet::new();
        if !callable_target(&guard.factory)
            || guard.required_named_arguments.is_empty()
            || guard
                .required_named_arguments
                .iter()
                .any(|required| required.name.trim().is_empty() || !names.insert(required.name.as_str()))
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "configured_argument_factory_guard requires a callable factory and unique, non-empty required named arguments",
            );
        }
        if let Some(pattern) = guard.factory.regex.as_deref() {
            if let Err(error) = Regex::new(pattern) {
                push_validation_issue(
                    issues,
                    "error",
                    "invalid-analysis-semantics",
                    Some(rule),
                    &format!("configured_argument_factory_guard.factory.regex is invalid: {error}"),
                );
            }
        }
    }
    if let Some(guard) = semantics.configured_argument_receiver_guard.as_ref() {
        let callable_target = |target: &RuleTarget| {
            target.name.as_ref().is_some_and(|name| !name.trim().is_empty())
                || target.attribute.as_ref().is_some_and(|parts| {
                    !parts.is_empty() && parts.iter().all(|part| !part.trim().is_empty())
                })
                || target
                    .regex
                    .as_ref()
                    .is_some_and(|regex| !regex.trim().is_empty())
        };
        let invalid_argument = |argument: &crate::rule::RequiredCallArgumentSemantics| {
            (!argument.require_static_value
                && argument.accepted_places.is_empty()
                && argument.accepted_static_values.is_empty())
                || argument
                    .accepted_places
                    .iter()
                    .any(|place| place.trim().is_empty())
        };
        if !callable_target(&guard.wrapper_factory)
            || !callable_target(&guard.provider_factory)
            || guard.required_calls.is_empty()
            || guard.required_calls.iter().any(|required| {
                let identity: AHashSet<_> = required.identity_argument_indices.iter().copied().collect();
                !callable_target(&required.call)
                    || identity.len() != required.identity_argument_indices.len()
                    || identity.iter().any(|index| {
                        !required
                            .required_arguments
                            .iter()
                            .any(|argument| argument.index == *index)
                    })
                    || required.required_arguments.iter().any(invalid_argument)
            })
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "configured_argument_receiver_guard requires callable wrapper/provider/required calls and exact argument requirements",
            );
        }
        for (role, target) in [
            ("wrapper_factory", &guard.wrapper_factory),
            ("provider_factory", &guard.provider_factory),
        ] {
            if let Some(pattern) = target.regex.as_deref() {
                if let Err(error) = Regex::new(pattern) {
                    push_validation_issue(
                        issues,
                        "error",
                        "invalid-analysis-semantics",
                        Some(rule),
                        &format!("configured_argument_receiver_guard.{role}.regex is invalid: {error}"),
                    );
                }
            }
        }
        for (index, required) in guard.required_calls.iter().enumerate() {
            if let Some(pattern) = required.call.regex.as_deref() {
                if let Err(error) = Regex::new(pattern) {
                    push_validation_issue(
                        issues,
                        "error",
                        "invalid-analysis-semantics",
                        Some(rule),
                        &format!(
                            "configured_argument_receiver_guard.required_calls[{index}].call.regex is invalid: {error}"
                        ),
                    );
                }
            }
        }
    }
    if semantics.character_escape.as_ref().is_some_and(|escape| {
        escape.required_mappings.is_empty()
            || escape
                .required_mappings
                .iter()
                .any(|mapping| mapping.input.is_empty() || mapping.output.is_empty())
    }) {
        push_validation_issue(
            issues,
            "error",
            "invalid-analysis-semantics",
            Some(rule),
            "character_escape requires non-empty input/output mappings",
        );
    }
    if let Some(guard) = semantics.url_network_guard.as_ref() {
        let callable_target = |target: &RuleTarget| {
            target.name.as_ref().is_some_and(|name| !name.trim().is_empty())
                || target.attribute.as_ref().is_some_and(|parts| {
                    !parts.is_empty() && parts.iter().all(|part| !part.trim().is_empty())
                })
                || target
                    .regex
                    .as_ref()
                    .is_some_and(|regex| !regex.trim().is_empty())
        };
        let component_valid = |component: &crate::rule::UrlComponentSemantics| {
            component
                .field
                .as_ref()
                .is_some_and(|field| !field.trim().is_empty())
                ^ component.accessor.as_ref().is_some_and(callable_target)
        };
        let root_valid = match &guard.root {
            crate::rule::UrlGuardRootSemantics::SinkReceiver
            | crate::rule::UrlGuardRootSemantics::SinkAssignmentTarget
            | crate::rule::UrlGuardRootSemantics::SinkArgumentParserInput { .. } => true,
            crate::rule::UrlGuardRootSemantics::SinkArgumentAccessor { accessor, .. } => {
                callable_target(accessor)
            }
        };
        let redirect_valid = guard.redirect.as_ref().is_none_or(|redirect| match redirect {
            crate::rule::UrlRedirectGuardSemantics::ReceiverFieldExactCallback {
                field,
                required_return_place,
            } => !field.trim().is_empty() && !required_return_place.trim().is_empty(),
            crate::rule::UrlRedirectGuardSemantics::PostSinkCall { call, .. } => callable_target(call),
            crate::rule::UrlRedirectGuardSemantics::CallArgumentFields { required_fields, .. } => {
                !required_fields.is_empty()
                    && required_fields.iter().all(|field| {
                        !field.path.is_empty() && field.path.iter().all(|part| !part.trim().is_empty())
                    })
            }
        });
        if !root_valid
            || !callable_target(&guard.parser)
            || !component_valid(&guard.scheme.component)
            || guard
                .scheme
                .comparison_predicate
                .as_ref()
                .is_some_and(|target| !callable_target(target))
            || guard.scheme.allowed_values.is_empty()
            || guard.scheme.allowed_values.iter().any(|value| value.is_empty())
            || guard
                .scheme
                .reconstructed_values
                .iter()
                .any(|value| value.is_empty())
            || !component_valid(&guard.host_allowlist.component)
            || guard
                .host_allowlist
                .membership_predicate
                .as_ref()
                .is_some_and(|target| !callable_target(target))
            || guard
                .host_allowlist
                .static_collection_factories
                .iter()
                .any(|target| !callable_target(target))
            || !callable_target(&guard.dns.resolver)
            || guard
                .dns
                .address_parser
                .as_ref()
                .is_some_and(|parser| !callable_target(&parser.target))
            || guard.dns.private_address_predicates.is_empty()
            || guard
                .dns
                .private_address_predicates
                .iter()
                .any(|target| !callable_target(target))
            || !redirect_valid
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "url_network_guard requires callable rule targets, exactly one field/accessor per component, non-empty allowed schemes/private-address predicates, and a valid redirect policy",
            );
        }
        let mut regex_targets: Vec<(&str, &RuleTarget)> = vec![("parser", &guard.parser)];
        if let Some(parser) = guard.dns.address_parser.as_ref() {
            regex_targets.push(("dns.address_parser", &parser.target));
        }
        if let crate::rule::UrlGuardRootSemantics::SinkArgumentAccessor { accessor, .. } = &guard.root {
            regex_targets.push(("root.accessor", accessor));
        }
        if let Some(target) = guard.scheme.component.accessor.as_ref() {
            regex_targets.push(("scheme.component.accessor", target));
        }
        if let Some(target) = guard.scheme.comparison_predicate.as_ref() {
            regex_targets.push(("scheme.comparison_predicate", target));
        }
        if let Some(target) = guard.host_allowlist.component.accessor.as_ref() {
            regex_targets.push(("host_allowlist.component.accessor", target));
        }
        if let Some(target) = guard.host_allowlist.membership_predicate.as_ref() {
            regex_targets.push(("host_allowlist.membership_predicate", target));
        }
        for target in &guard.host_allowlist.static_collection_factories {
            regex_targets.push(("host_allowlist.static_collection_factories", target));
        }
        regex_targets.push(("dns.resolver", &guard.dns.resolver));
        for target in &guard.dns.private_address_predicates {
            regex_targets.push(("dns.private_address_predicates", target));
        }
        if let Some(crate::rule::UrlRedirectGuardSemantics::PostSinkCall { call, .. }) =
            guard.redirect.as_ref()
        {
            regex_targets.push(("redirect.call", call));
        }
        for (role, target) in regex_targets {
            if let Some(pattern) = target.regex.as_deref() {
                if let Err(error) = Regex::new(pattern) {
                    push_validation_issue(
                        issues,
                        "error",
                        "invalid-analysis-semantics",
                        Some(rule),
                        &format!("url_network_guard.{role}.regex is invalid: {error}"),
                    );
                }
            }
        }
    }
    if let Some(guard) = semantics.url_reconstruction_guard.as_ref() {
        let callable_target = |target: &RuleTarget| {
            target.name.as_ref().is_some_and(|name| !name.trim().is_empty())
                || target.attribute.as_ref().is_some_and(|parts| {
                    !parts.is_empty() && parts.iter().all(|part| !part.trim().is_empty())
                })
                || target
                    .regex
                    .as_ref()
                    .is_some_and(|regex| !regex.trim().is_empty())
        };
        let exact_component = |component: &crate::rule::UrlComponentSemantics| match (
            component.field.as_deref(),
            component.accessor.as_ref(),
        ) {
            (Some(field), None) => !field.trim().is_empty(),
            (None, Some(accessor)) => callable_target(accessor),
            _ => false,
        };
        let required_names: AHashSet<_> = guard
            .required_sink_named_arguments
            .iter()
            .map(|argument| argument.name.trim())
            .collect();
        if !callable_target(&guard.parser)
            || !exact_component(&guard.scheme.component)
            || guard
                .scheme
                .comparison_predicate
                .as_ref()
                .is_some_and(|target| !callable_target(target))
            || guard.scheme.allowed_values.is_empty()
            || guard.scheme.allowed_values.iter().any(|value| value.is_empty())
            || guard
                .scheme
                .reconstructed_values
                .iter()
                .any(|value| value.is_empty())
            || !exact_component(&guard.host_allowlist.component)
            || guard
                .host_allowlist
                .membership_predicate
                .as_ref()
                .is_some_and(|target| !callable_target(target))
            || guard
                .host_allowlist
                .static_collection_factories
                .iter()
                .any(|target| !callable_target(target))
            || !exact_component(&guard.path_component)
            || guard
                .path_fallback
                .as_ref()
                .is_some_and(|fallback| fallback.is_empty())
            || guard.redirect.as_ref().is_some_and(|redirect| match redirect {
                crate::rule::UrlRedirectGuardSemantics::ReceiverFieldExactCallback {
                    field,
                    required_return_place,
                } => field.trim().is_empty() || required_return_place.trim().is_empty(),
                crate::rule::UrlRedirectGuardSemantics::PostSinkCall { call, .. } => !callable_target(call),
                crate::rule::UrlRedirectGuardSemantics::CallArgumentFields { required_fields, .. } => {
                    required_fields.is_empty()
                        || required_fields.iter().any(|field| {
                            field.path.is_empty() || field.path.iter().any(|part| part.trim().is_empty())
                        })
                }
            })
            || required_names.len() != guard.required_sink_named_arguments.len()
            || required_names.iter().any(|name| name.is_empty())
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "url_reconstruction_guard requires callable parser/static-collection targets, exact field-or-accessor components, non-empty allowed schemes/path fallback, and unique non-empty sink argument names",
            );
        }
        for (role, target) in std::iter::once(("parser", &guard.parser))
            .chain(
                guard
                    .host_allowlist
                    .static_collection_factories
                    .iter()
                    .map(|target| ("host_allowlist.static_collection_factories", target)),
            )
            .chain(guard.redirect.iter().filter_map(|redirect| match redirect {
                crate::rule::UrlRedirectGuardSemantics::PostSinkCall { call, .. } => {
                    Some(("redirect.call", call.as_ref()))
                }
                crate::rule::UrlRedirectGuardSemantics::ReceiverFieldExactCallback { .. } => None,
                crate::rule::UrlRedirectGuardSemantics::CallArgumentFields { .. } => None,
            }))
        {
            if let Some(pattern) = target.regex.as_deref() {
                if let Err(error) = Regex::new(pattern) {
                    push_validation_issue(
                        issues,
                        "error",
                        "invalid-analysis-semantics",
                        Some(rule),
                        &format!("url_reconstruction_guard.{role}.regex is invalid: {error}"),
                    );
                }
            }
        }
    }
    if let Some(context) = semantics.context_flow.as_ref() {
        if context.channel.trim().is_empty()
            || context.value_label.trim().is_empty()
            || context.parameter_name.trim().is_empty()
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "analysis_semantics.context_flow requires non-empty channel, value_label, and parameter_name",
            );
        }
        if context.sanitized_rewrite_clears_channel
            && (context.role != ContextFlowRole::Producer
                || context.rewrite_source_rule_ids.is_empty()
                || context
                    .rewrite_source_rule_ids
                    .iter()
                    .any(|rule_id| rule_id.trim().is_empty()))
        {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "a sanitized context rewrite requires producer role and non-empty rewrite_source_rule_ids",
            );
        }
        if !context.sanitized_rewrite_clears_channel && !context.rewrite_source_rule_ids.is_empty() {
            push_validation_issue(
                issues,
                "error",
                "invalid-analysis-semantics",
                Some(rule),
                "rewrite_source_rule_ids requires sanitized_rewrite_clears_channel",
            );
        }
    }
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
        if let crate::rule::ConstraintKind::ArgSequenceItemsEqual {
            arg_sequence_items_equal,
        } = constraint
        {
            let mut indices = AHashSet::new();
            if arg_sequence_items_equal.items.is_empty()
                || arg_sequence_items_equal
                    .items
                    .iter()
                    .any(|item| item.accepted_values.is_empty() || !indices.insert(item.index))
            {
                push_validation_issue(
                    issues,
                    "error",
                    "invalid-constraint",
                    Some(rule),
                    "arg_sequence_items_equal requires non-empty, uniquely indexed accepted values",
                );
            }
        }
        let regex = match constraint {
            crate::rule::ConstraintKind::ReceiverMatchesRegex {
                receiver_matches_regex,
            } => Some((
                "constraints.receiver_matches_regex",
                receiver_matches_regex.as_str(),
            )),
            crate::rule::ConstraintKind::ReceiverNotMatchesRegex {
                receiver_not_matches_regex,
            } => Some((
                "constraints.receiver_not_matches_regex",
                receiver_not_matches_regex.as_str(),
            )),
            crate::rule::ConstraintKind::UnlessPriorReceiverCall {
                unless_prior_receiver_call,
            } => Some((
                "constraints.unless_prior_receiver_call.static_string_args_regex",
                unless_prior_receiver_call.static_string_args_regex.as_str(),
            )),
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
            | crate::rule::ConstraintKind::ReceiverOriginCallbackParamReachesCall { .. }
            | crate::rule::ConstraintKind::ReceiverFactoryArgumentFieldsEqual { .. }
            | crate::rule::ConstraintKind::FormatArgIndex { .. }
            | crate::rule::ConstraintKind::Namespace { .. }
            | crate::rule::ConstraintKind::TopLevel { .. }
            | crate::rule::ConstraintKind::ArgCount { .. }
            | crate::rule::ConstraintKind::MinArgs { .. }
            | crate::rule::ConstraintKind::MaxArgs { .. }
            | crate::rule::ConstraintKind::ArgValueNotAggregate { .. }
            | crate::rule::ConstraintKind::ArgSequenceItemsEqual { .. }
            | crate::rule::ConstraintKind::SameReceiverCallCountAtLeast { .. }
            | crate::rule::ConstraintKind::ArgLt { .. }
            | crate::rule::ConstraintKind::ArgLe { .. }
            | crate::rule::ConstraintKind::ArgGt { .. }
            | crate::rule::ConstraintKind::ArgGe { .. }
            | crate::rule::ConstraintKind::RequiresRuntimeType { .. }
            | crate::rule::ConstraintKind::EnclosingDecoratorIn { .. }
            | crate::rule::ConstraintKind::EnclosingModifierIn { .. }
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
    signal == token || bonsai_common::short_qualified_tail(signal) == token
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
        MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param | MatchKind::Type => {
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
    if let Some(default_call) = &target.default_call {
        return format!("default-call:{default_call}");
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
