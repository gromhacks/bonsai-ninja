//! Findings — a source→sink match with stable `S:` content-hash id.
//!
//! `S:` id construction: FNV-1a-64 low 32 bits over
//! `[source_id, sink_id, group_id, language]`. Stable across runs, cache
//! state, and render mode; changes only when the rule identity or the
//! chain-group identity changes.

use crate::matcher::RuleMatch;
use crate::rule::{Rule, Severity};
use bonsai_hash::fnv1a_names64;
use serde::Serialize;

/// Sanitizer outcome on the chain. Drives review priority and
/// rendering — sanitization means the developer attempted to filter,
/// not that the value is safe (see security-spec.mdx "Sanitized Does
/// Not Mean Safe"). Findings are surfaced regardless; status governs
/// where they appear and at what severity floor.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingStatus {
    /// No sanitizer credited the sink tag on any chain. Full severity,
    /// main findings list.
    Unsanitized,
    /// At least one sanitizer credited the sink tag. Severity floor
    /// applied; rendered in a separate "review for bypass" section.
    Sanitized,
    /// Sanitizer fired on the chain but its tag does NOT credit the
    /// sink tag (e.g. HTML-encoded value used in URL context). Full
    /// severity preserved + a WRONG-CONTEXT warning, because the
    /// developer thought they were protected.
    WrongContext,
}

impl FindingStatus {
    /// Stable kebab-case string for serialization and rendering.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsanitized => "unsanitized",
            Self::Sanitized => "sanitized",
            Self::WrongContext => "wrong-context",
        }
    }

    /// Merge rank for grouping: when several findings collapse into
    /// one group, the LEAST-mitigated path wins (any Unsanitized chain
    /// drags the whole group to Unsanitized).
    fn merge_rank(self) -> u8 {
        match self {
            Self::Unsanitized => 2,
            Self::WrongContext => 1,
            Self::Sanitized => 0,
        }
    }

    /// Combine two statuses for the same group: pick the
    /// least-mitigated of the two.
    pub fn merge(self, other: Self) -> Self {
        if self.merge_rank() >= other.merge_rank() {
            self
        } else {
            other
        }
    }
}

impl Default for FindingStatus {
    fn default() -> Self {
        Self::Unsanitized
    }
}

/// One match site on either side of a finding. Mirrors the spec's
/// `match_site` block.
#[derive(Clone, Debug, Serialize)]
pub struct FindingMatch {
    pub rule_id: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_fn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub payload_types: Vec<String>,
    /// Sink-side: the per-arg taint evidence at this sink call site.
    /// Source / sanitizer sides leave this empty. Lets the consumer
    /// (LLM or human) tell "URL is tainted" from "body is tainted"
    /// without re-parsing the call.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tainted_args: Vec<TaintedArgInfo>,
    /// Sanitizer-side: arg indices the sanitizer rule's discriminating
    /// constraint named (`arg_matches_regex` / `arg_equals` /
    /// `keyword_arg_equals`). Lets the consumer tell which arg got
    /// wrapped — `format(safe, raw)` reports `[0]` so reviewers know
    /// arg 1 still flows raw. Empty when the sanitizer cleanses by
    /// call shape alone (no arg-pointing constraint).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sanitised_arg_indices: Vec<u32>,
}

/// Per-arg taint evidence rendered on the sink side of a finding. The
/// SHAPE of evidence — bonsai surfaces it, the consumer (LLM or
/// human) interprets it.
#[derive(Clone, Debug, Serialize, Default)]
pub struct TaintedArgInfo {
    /// Positional index in the call's argument list (`usize::MAX` for
    /// receiver, in keeping with the dump command's convention).
    pub index: usize,
    /// The argument's identifier text as it appeared in source.
    pub value_text: String,
}

/// One taint-propagation edge preserved for report consumers. Unlike the
/// display-only function chain, this names the concrete call site and
/// every argument the taint engine propagated across that edge.
#[derive(Clone, Debug, Serialize, Default)]
pub struct TaintPropagationStep {
    pub caller: String,
    pub callee: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tainted_args: Vec<TaintPropagationArg>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct TaintPropagationArg {
    pub index: usize,
    pub value_text: String,
    pub param_name: String,
}

impl FindingMatch {
    /// Build a match site from a matcher hit + the rule that fired,
    /// stamping rule-derived metadata (tag, severity, trust, payload
    /// types) onto the location data.
    pub fn from_rule_match(rule_match: &RuleMatch, rule: &Rule) -> Self {
        Self {
            rule_id: rule_match.rule_id.clone(),
            file: rule_match.file.clone(),
            line: rule_match.line,
            column: rule_match.column,
            text: rule_match.match_text.clone(),
            enclosing_fn: rule_match.enclosing_fn.clone(),
            tag: rule.tag.clone(),
            severity: rule.severity,
            category: rule.category.clone(),
            trust: rule.trust.map(|trust_class| trust_class.as_str().to_string()),
            payload_types: rule
                .payload_types
                .iter()
                .map(|payload_type| payload_type.as_str().to_string())
                .collect(),
            tainted_args: Vec::new(),
            sanitised_arg_indices: sanitised_indices_from_rule(rule),
        }
    }

    /// Build a synthetic match site for a source that isn't declared
    /// in the rulepack — specifically the inferred entry-point
    /// parameter sources produced by
    /// `matcher::infer_entry_point_sources`. Carries the "local"
    /// trust tag (the param's taint origin is known to be user input
    /// but without framework context we can't prove "remote") and
    /// leaves rulepack-derived fields at defaults.
    #[must_use]
    pub fn from_inferred(rule_match: &RuleMatch) -> Self {
        Self {
            rule_id: rule_match.rule_id.clone(),
            file: rule_match.file.clone(),
            line: rule_match.line,
            column: rule_match.column,
            text: rule_match.match_text.clone(),
            enclosing_fn: rule_match.enclosing_fn.clone(),
            tag: Some("entry-point".to_string()),
            severity: None,
            category: Some("inferred".to_string()),
            trust: Some("local".to_string()),
            payload_types: Vec::new(),
            tainted_args: Vec::new(),
            sanitised_arg_indices: Vec::new(),
        }
    }
}

/// Extract every arg index named by an arg-pointing constraint on a
/// rule (P2 — sanitiser per-arg attribution). When the rule has no
/// such constraint, returns an empty vec — the rule cleanses by call
/// shape alone, not by a specific arg.
fn sanitised_indices_from_rule(rule: &Rule) -> Vec<u32> {
    use crate::rule::ConstraintKind;
    let mut indices: Vec<u32> = Vec::new();
    for constraint in rule.constraints.0.iter() {
        let index = match constraint {
            ConstraintKind::ArgEquals { arg_equals } => Some(arg_equals.index),
            ConstraintKind::ArgMatchesRegex { arg_matches_regex } => Some(arg_matches_regex.index),
            ConstraintKind::ArgNotMatchesRegex {
                arg_not_matches_regex,
            } => Some(arg_not_matches_regex.index),
            ConstraintKind::FormatArgIndex { format_arg_index } => Some(*format_arg_index),
            ConstraintKind::SecondArgEquals { .. } => Some(1),
            ConstraintKind::ArgLt { arg_lt } => Some(arg_lt.index),
            ConstraintKind::ArgLe { arg_le } => Some(arg_le.index),
            ConstraintKind::ArgGt { arg_gt } => Some(arg_gt.index),
            ConstraintKind::ArgGe { arg_ge } => Some(arg_ge.index),
            // KeywordArgEquals / ArgTainted / others either don't pin
            // a positional index or aren't sanitiser-relevant.
            _ => None,
        };
        if let Some(idx) = index {
            if !indices.contains(&idx) {
                indices.push(idx);
            }
        }
    }
    indices
}

/// One finding — a source / sink pair observed on at least one chain
/// through the workspace.
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub finding_id: String,
    pub language: String,
    pub source: FindingMatch,
    pub sink: FindingMatch,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sanitizers_seen: Vec<FindingMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representative_flow_id: Option<String>,
    /// Whether this finding's source-to-sink evidence was computed to
    /// completion for the requested semantic scope. Public findings are
    /// emitted only from complete semantic evidence; the explicit field keeps
    /// downstream consumers from having to infer that from absence of broad
    /// precision.
    pub analysis_complete: bool,
    /// Machine-readable reasons when `analysis_complete` is false. Kept even
    /// when empty so JSON consumers can treat taint-analysis and
    /// source-analysis rows uniformly.
    pub analysis_incomplete_reasons: Vec<String>,
    /// Function-level chain (entry → … → sink-enclosing-fn) for this
    /// finding's representative flow. Empty for pattern-only findings
    /// and direct cases without a multi-hop resolved lineage.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_display: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_path: Vec<TaintPropagationStep>,
    /// Full source body of each function along the flow, with `step`/`role`
    /// marked on the lines that carry a flow event - the same code the text
    /// view prints. Empty for findings without a resolved multi-hop chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hops: Vec<crate::flow_evidence::FlowFunctionBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    pub precision: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub owasp: Vec<String>,
    /// Sanitizer outcome on the chain — see [`FindingStatus`] for the
    /// three variants and their rendering contract. Always serialized
    /// (no skip-if), so consumers can switch on it without nullable
    /// handling.
    #[serde(default)]
    pub status: FindingStatus,
    /// True when the source OR sink file path matches a common test
    /// convention (`test/`, `tests/`, `*_test.go`, `*Test*.java`,
    /// `Tests/` Xcode style, `__tests__/`, `*.spec.ts`, etc.). Lets
    /// reviewers and the CLI's `--exclude-tests` flag drop test-only
    /// findings without re-parsing paths.
    #[serde(default, skip_serializing_if = "is_false")]
    pub from_test: bool,
}

/// Serde callback for `#[serde(skip_serializing_if = "is_false")]` —
/// elides boolean fields when they hold the default `false` value.
#[allow(clippy::trivially_copy_pass_by_ref)] // serde `skip_serializing_if` callback signature
fn is_false(value: &bool) -> bool {
    !value
}

/// True when `path` looks like a test-convention file. Centralised
/// across the codebase so security findings, rule classification, and
/// the CLI's `--exclude-tests` filter all agree.
///
/// The pattern set is kept in lockstep with the test-related entries
/// in `crates/cli/src/commands/security.rs::PRODUCTION_EXCLUDES` so
/// `--exclude-tests` and `--profile production` classify the same
/// files as test code. PRODUCTION_EXCLUDES is broader (it also
/// excludes vendored deps, build outputs, generated code, etc.); this
/// helper is the test-only subset.
#[must_use]
#[allow(clippy::case_sensitive_file_extension_comparisons)] // input is pre-lowercased
pub(crate) fn path_is_test_file(path: &str) -> bool {
    let lowercase = path.to_ascii_lowercase();
    // Normalise Windows-emitted backslash separators so segment
    // matching works regardless of the adapter's path encoding.
    let lowercase = lowercase.replace('\\', "/");
    // Explicit segment match: cross-language test/fixture/mock
    // directory conventions (kept in lockstep with PRODUCTION_EXCLUDES).
    let test_segments = [
        "/test/",
        "/tests/",
        "/__tests__/",
        "/__mocks__/",
        "/spec/",
        "/specs/",
        "/testing/",
        "/testsuite/",
        "/fixture/",
        "/fixtures/",
        "/mock/",
        "/mocks/",
        "/e2e/",
        "/integration/",
        "/acceptance/",
        // JVM Maven/Gradle layout.
        "/src/test/",
        "/src/it/",
        "/androidtest/",
        // JS/TS test runners.
        "/cypress/",
        "/playwright/",
        "/storybook/",
        "/.storybook/",
        // Python conventional pytest fixture directory.
        "/conftest/",
    ];
    if test_segments.iter().any(|segment| lowercase.contains(segment)) {
        return true;
    }
    // Suffix conventions per language. Strip directory prefix so the
    // basename checks below match regardless of where the file lives.
    let basename = lowercase
        .rsplit_once('/')
        .map(|(_, name)| name)
        .unwrap_or(lowercase.as_str());
    if basename == "conftest.py" {
        return true;
    }
    if basename.ends_with("_test.go")
        || basename.ends_with("_test.py")
        || basename.ends_with(".test.ts")
        || basename.ends_with(".test.js")
        || basename.ends_with(".test.tsx")
        || basename.ends_with(".test.jsx")
        || basename.ends_with(".spec.ts")
        || basename.ends_with(".spec.js")
        || basename.ends_with(".spec.tsx")
        || basename.ends_with(".spec.jsx")
        || basename.ends_with(".spec.rb")
        || basename.ends_with("test.java")
        || basename.ends_with("tests.java")
        || basename.ends_with("it.java")
        || basename.ends_with("integrationtest.java")
        || basename.ends_with("spec.scala")
        || basename.ends_with("test.scala")
        || basename.ends_with("tests.scala")
        || basename.ends_with("test.kt")
        || basename.ends_with("tests.kt")
        || basename.ends_with("it.kt")
        || basename.ends_with("tests.cs")
        || basename.ends_with("test.cs")
        || basename.ends_with("_spec.rb")
        || basename.ends_with("_test.rb")
        || basename.ends_with("_test.exs")
        || basename.ends_with("_test.ex")
        || basename.ends_with(".t")
    // Perl test convention
    {
        return true;
    }
    false
}

/// Compute the stable `S:` finding id.
///
/// Inputs are the rule ids + group id + language — the same tokens the
/// spec prescribes. Kept as a pure function so tests can verify id
/// stability in isolation.
#[must_use]
pub fn compute_finding_id(source_id: &str, sink_id: &str, group_id: &str, language: &str) -> String {
    let tokens = [
        source_id.to_string(),
        sink_id.to_string(),
        group_id.to_string(),
        language.to_string(),
    ];
    format!("S:{:016x}", fnv1a_names64(&tokens))
}
