//! Compile a rule into the `inspect` flag set it corresponds to.
//!
//! Security mode **does not** invent a second filter language. For every
//! source / sink selection pair, the wrapper produces a
//! [`CompiledRule`] whose fields map 1:1 to the subset of `inspect` flags
//! documented in `docs/security-spec.mdx § Wrapper compilation model`.

use crate::rule::{MatchKind, Rule, RuleKind};

/// A rule compiled into inspect-flag-shaped knobs. The CLI / library
/// consumer plugs these into an `inspect` invocation or a library call.
#[derive(Clone, Debug, Default)]
pub struct CompiledRule {
    /// The `--query` / primary-matcher needle (callee name or target).
    pub query: Option<String>,
    /// `--regex` when the source rule supplied a regex callee.
    pub regex: bool,
    /// `--from` needle (for source rules).
    pub from: Option<String>,
    /// `--from-kind` narrower.
    pub from_kind: Option<String>,
    /// `--to` needle (for sink rules).
    pub to: Option<String>,
    /// `--to-kind` narrower.
    pub to_kind: Option<String>,
    /// `--kind <k>` fact filter.
    pub kind: Option<String>,
}

impl CompiledRule {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.query.is_none() && self.from.is_none() && self.to.is_none() && self.kind.is_none()
    }
}

/// Compile one rule. The output shape depends on which side of a finding
/// the rule plays — source rules populate `from` + `from_kind`; sink
/// rules populate `query` + `to` + `to_kind`; sanitizers compile to a
/// no-op (they're attached during post-processing, not during query).
#[must_use]
pub fn compile_rule_to_inspect_args(rule: &Rule) -> CompiledRule {
    let mut compiled = CompiledRule::default();
    let needle = rule_needle(rule);
    let kind_str = kind_to_string(rule.match_spec.kind);
    match rule.kind {
        RuleKind::Source => {
            compiled.from.clone_from(&needle);
            compiled.from_kind = Some(kind_str.to_string());
        }
        RuleKind::Sink => {
            compiled.query.clone_from(&needle);
            compiled.to = needle;
            compiled.to_kind = Some(kind_str.to_string());
            compiled.kind = Some(kind_str.to_string());
        }
        RuleKind::Sanitizer => {
            // Sanitizers are evidence, not a query — leave every field
            // empty. See `crate::finding::attach_sanitizers`.
        }
        RuleKind::Typing => {
            // Typing rules are not a query either — they feed rulepack-owned
            // compiler models, not inspect/finding output.
        }
    }
    // Regex-qualifier propagation: a rule whose callee/target is a regex
    // tells the caller to pass `--regex` alongside the needle.
    let target = match rule.match_spec.kind {
        MatchKind::Call | MatchKind::New | MatchKind::Missing => rule.match_spec.callee.as_ref(),
        MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param | MatchKind::Type => {
            rule.match_spec.target.as_ref()
        }
    };
    if let Some(rule_target) = target {
        if rule_target.regex.is_some() {
            compiled.regex = true;
        }
    }
    compiled
}

/// Extract the primary search needle from a rule's match spec — the
/// regex string when present, else the tail of an attribute chain,
/// else the bare name.
fn rule_needle(rule: &Rule) -> Option<String> {
    let target = match rule.match_spec.kind {
        MatchKind::Call | MatchKind::New | MatchKind::Missing => rule.match_spec.callee.as_ref()?,
        MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param | MatchKind::Type => {
            rule.match_spec.target.as_ref()?
        }
    };
    if let Some(regex) = target.regex.as_deref() {
        return Some(regex.to_string());
    }
    if let Some(attribute) = target.attribute.as_ref() {
        // Pick the tail element — inspect does its own tail / namespace
        // fuzzy match. Preserves `--query system` behavior.
        return attribute.last().cloned();
    }
    target.name.clone()
}

/// Map a `MatchKind` to the inspect `--kind` flag value. `New` collapses
/// onto `call` because inspect's fact taxonomy treats constructor calls
/// as the same family as ordinary calls.
fn kind_to_string(match_kind: MatchKind) -> &'static str {
    match match_kind {
        MatchKind::Call => "call",
        MatchKind::New => "call",
        MatchKind::Read => "read",
        MatchKind::Write => "write",
        MatchKind::Return => "return",
        MatchKind::Param => "decl",
        MatchKind::Type => "type",
        // Missing rules drive the inspect query the same way Call/New do —
        // the matcher then inverts the result (rule fires when the listed
        // callee is ABSENT on a path).
        MatchKind::Missing => "call",
    }
}
