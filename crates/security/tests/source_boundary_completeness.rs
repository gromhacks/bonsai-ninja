//! Release gates for source-boundary and compiler-fact completeness.
//!
//! A large aggregate source-rule count can hide an entirely absent trust
//! boundary for one language.  These assertions operate on the source-owned
//! family files and applicability metadata so a missing cell or an adapter
//! TODO cannot disappear inside the global rule total.

use bonsai_security::{load_rulepack, pack_audit, rule::RuleTarget, RuleKind};
use std::path::PathBuf;
use std::{collections::BTreeSet, fmt::Write as _};

fn rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("security-patterns")
}

#[test]
fn every_language_has_an_enabled_rule_for_every_canonical_source_boundary() {
    let pack = load_rulepack(&rules_dir()).expect("load source-controlled rulepack");
    let report = pack_audit(&pack, None);
    assert_eq!(
        report.languages.len(),
        20,
        "all bundled languages must participate"
    );

    let mut gaps = Vec::new();
    for language in &report.languages {
        for family in &report.canonical_source_families {
            let count = language
                .source_families
                .get(family)
                .unwrap_or_else(|| panic!("{}: missing canonical source family {family}", language.language));
            if !count.not_applicable && count.enabled == 0 {
                gaps.push(format!(
                    "{}/{} ({} disabled)",
                    language.language, family, count.disabled
                ));
            }
        }
    }

    assert!(
        gaps.is_empty(),
        "canonical source boundaries with no enabled exact rule:\n{}",
        gaps.join("\n")
    );
}

#[test]
fn every_language_has_an_enabled_rule_for_every_applicable_canonical_sink_family() {
    let pack = load_rulepack(&rules_dir()).expect("load source-controlled rulepack");
    let report = pack_audit(&pack, None);
    let mut gaps = Vec::new();

    for language in &report.languages {
        for family in &report.canonical_sink_families {
            let count = language
                .sinks
                .get(family)
                .unwrap_or_else(|| panic!("{}: missing canonical sink family {family}", language.language));
            if !count.not_applicable && count.enabled == 0 {
                gaps.push(format!(
                    "{}/{} ({} disabled)",
                    language.language, family, count.disabled
                ));
            }
        }
    }

    assert!(
        gaps.is_empty(),
        "canonical sink families with no enabled exact rule:\n{}",
        gaps.join("\n")
    );
}

#[test]
fn every_language_has_at_least_one_enabled_sanitizer_boundary() {
    let pack = load_rulepack(&rules_dir()).expect("load source-controlled rulepack");
    let report = pack_audit(&pack, None);
    let gaps = report
        .languages
        .iter()
        .filter(|language| language.sanitizers.enabled == 0)
        .map(|language| {
            format!(
                "{} ({} disabled)",
                language.language, language.sanitizers.disabled
            )
        })
        .collect::<Vec<_>>();

    assert!(
        gaps.is_empty(),
        "languages with no enabled sanitizer boundary:\n{}",
        gaps.join("\n")
    );
}

#[test]
fn bundled_rulepack_contains_only_executable_rules() {
    let pack = load_rulepack(&rules_dir()).expect("load source-controlled rulepack");
    let mut disabled = pack
        .all_rules()
        .into_iter()
        .filter(|rule| !rule.enabled)
        .map(|rule| format!("{} ({})", rule.id, rule.source_path))
        .collect::<Vec<_>>();
    disabled.sort();

    assert!(
        disabled.is_empty(),
        "the bundled pack must contain only executable rules; represent genuine family exclusions in metadata and remove duplicates/speculative matches:\n{}",
        disabled.join("\n")
    );
}

#[test]
fn applicability_metadata_names_only_canonical_unimplemented_families() {
    let pack = load_rulepack(&rules_dir()).expect("load source-controlled rulepack");
    let report = pack_audit(&pack, None);
    let source_families = report
        .canonical_source_families
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let sink_families = report
        .canonical_sink_families
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut problems = String::new();

    for language in &report.languages {
        for (family, count) in &language.source_families {
            if count.not_applicable && count.enabled != 0 {
                let _ = writeln!(
                    problems,
                    "{}/source/{family} is marked n/a but has {} executable rule(s)",
                    language.language, count.enabled
                );
            }
        }
        for (family, count) in &language.sinks {
            if count.not_applicable && count.enabled != 0 {
                let _ = writeln!(
                    problems,
                    "{}/sink/{family} is marked n/a but has {} executable rule(s)",
                    language.language, count.enabled
                );
            }
        }
    }

    for (language, metadata) in &pack.metadata.languages {
        let unique_sources = metadata
            .not_applicable_source_families
            .iter()
            .collect::<BTreeSet<_>>();
        if unique_sources.len() != metadata.not_applicable_source_families.len() {
            let _ = writeln!(problems, "{language}: duplicate n/a source family metadata");
        }
        let unique_sinks = metadata
            .not_applicable_sink_families
            .iter()
            .collect::<BTreeSet<_>>();
        if unique_sinks.len() != metadata.not_applicable_sink_families.len() {
            let _ = writeln!(problems, "{language}: duplicate n/a sink family metadata");
        }
        for family in &metadata.not_applicable_source_families {
            if !source_families.contains(family.as_str()) {
                let _ = writeln!(problems, "{language}: unknown n/a source family `{family}`");
            }
        }
        for family in &metadata.not_applicable_sink_families {
            if !sink_families.contains(family.as_str()) {
                let _ = writeln!(problems, "{language}: unknown n/a sink family `{family}`");
            }
        }
    }

    assert!(
        problems.is_empty(),
        "applicability metadata must be canonical and must not hide executable coverage:\n{problems}"
    );
}

#[test]
fn context_sensitive_source_rules_have_positive_and_collision_negative_examples() {
    fn target_requires_collision_negative(target: &RuleTarget) -> bool {
        !target.base_name_in.is_empty()
            || !target.base_name_not_in.is_empty()
            || target.binding_origin.is_some()
            || target.annotation.is_some()
            || target.default_call.is_some()
            || !target.in_class.is_empty()
            || !target.in_class_suffix.is_empty()
            || !target.in_owner_base.is_empty()
            || !target.in_method.is_empty()
            || !target.in_method_prefix.is_empty()
            || !target.param_index_in.is_empty()
            || !target.param_index_not_in.is_empty()
            || !target.param_type_in.is_empty()
            || !target.param_type_exact_in.is_empty()
            || !target.signature_param_types.is_empty()
            || !target.signature_param_annotations.is_empty()
            || !target.param_count_in.is_empty()
            || !target.base_param_index_in.is_empty()
            || !target.receiver_type_in.is_empty()
            || !target.decl_kind_in.is_empty()
            || !target.visibility_in.is_empty()
            || !target.call_kind_in.is_empty()
    }

    let pack = load_rulepack(&rules_dir()).expect("load source-controlled rulepack");
    let mut missing_positive = Vec::new();
    let mut missing_negative = Vec::new();

    for rule in pack
        .all_rules()
        .into_iter()
        .filter(|rule| rule.kind == RuleKind::Source && rule.enabled)
    {
        let requires_collision_negative = rule
            .match_spec
            .target
            .as_ref()
            .is_some_and(target_requires_collision_negative)
            || rule
                .match_spec
                .callee
                .as_ref()
                .is_some_and(target_requires_collision_negative)
            || !rule.constraints.is_empty()
            || !rule.callback_param_types.is_empty()
            || rule.callback_arg_index.is_some()
            || !rule.callback_field_path.is_empty();
        if !requires_collision_negative {
            continue;
        }
        let has_positive = rule.match_examples.iter().any(|example| !example.expect_no_match);
        let has_negative = rule.match_examples.iter().any(|example| example.expect_no_match);
        if !has_positive {
            missing_positive.push(format!("{} ({})", rule.id, rule.source_path));
        }
        if !has_negative {
            missing_negative.push(format!("{} ({})", rule.id, rule.source_path));
        }
    }

    assert!(
        missing_positive.is_empty(),
        "context-sensitive source rules without a positive compiler fixture:\n{}",
        missing_positive.join("\n")
    );
    assert!(
        missing_negative.is_empty(),
        "context-sensitive source rules without a collision-negative compiler fixture:\n{}",
        missing_negative.join("\n")
    );
}
