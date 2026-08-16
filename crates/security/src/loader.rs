//! Rulepack loader — walks a `security-patterns/` directory, validates
//! every rule, and returns a language-keyed [`Rulepack`].
//!
//! Hard rules enforced here:
//!   * `sources/` rules get `kind = Source`, `sinks/` gets `Sink`,
//!     `sanitizers/` gets `Sanitizer`, and `typing/` gets `Typing`. The `kind` is always
//!     directory-derived — rules can't lie about their family.
//!   * Language can come from either the `langs/<lang>/` directory
//!     wrapper OR a YAML `language:` field (custom rulepack projects
//!     use the latter). When both are present they must match. When
//!     neither is, the rule is rejected.
//!   * Duplicate rule ids within the same language are rejected.
//!   * `match.kind == call | new` requires `callee`; `read | write |
//!     return | param` requires `target`.
//!   * Tautological match regexes are rejected. Sink constraints are not
//!     required: taint reachability, not argument-shape gating, is the
//!     source of truth for sink findings.

use crate::rule::{AnalysisSemantics, MatchKind, Rule, RuleKind, Severity, TrustClass};
use ahash::AHashMap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// A language's loaded rules, partitioned by family.
#[derive(Clone, Debug, Default)]
pub struct LanguagePack {
    pub language: String,
    pub sources: Vec<Rule>,
    pub sinks: Vec<Rule>,
    pub sanitizers: Vec<Rule>,
    /// Typing-only rules (`typing/` dir, `RuleKind::Typing`). They feed the
    /// rulepack-owned compiler model via `build_rulepack_typing` and
    /// `all_rules()`, but never appear in a finding/inventory path. See
    /// [`RuleKind::Typing`].
    pub typing: Vec<Rule>,
}

/// Rulepack-owned ecosystem and taxonomy data that is not a source/sink rule
/// by itself. Keeping this beside the YAML rules prevents shared crates from
/// accumulating package-manager filenames, distribution aliases, or
/// language-specific security-model exceptions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulepackMetadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canonical_sink_families: Vec<String>,
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub sink_family_short_labels: AHashMap<String, String>,
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub sink_family_aliases: AHashMap<String, String>,
    /// Sanitizer tag -> sink tags for which that sanitizer is relevant.
    /// Same-tag credit is implicit. An empty target list declares a known
    /// inventory/passthrough tag that intentionally clears no sink family.
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub sanitizer_credits: AHashMap<String, Vec<String>>,
    /// Pack-wide defaults inherited by sink rules with the matching tag.
    /// Per-language defaults and explicit rule fields take precedence.
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub sink_tag_semantics: AHashMap<String, AnalysisSemantics>,
    /// Pack-wide defaults inherited by sink rules with the matching category.
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub sink_category_semantics: AHashMap<String, AnalysisSemantics>,
    /// Pack-wide defaults inherited by sanitizer rules with the matching tag.
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub sanitizer_tag_semantics: AHashMap<String, AnalysisSemantics>,
    /// Named CLI/security profile defaults. File inventories and policy
    /// values live in rulepack data so the CLI does not compile ecosystem
    /// layouts or deployment assumptions into the binary.
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub profiles: AHashMap<String, SecurityProfileMetadata>,
    /// Workspace-relative patterns used to classify test findings. The
    /// matcher is generic; language/ecosystem filename conventions live here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub test_path_patterns: Vec<String>,
    #[serde(default)]
    pub languages: AHashMap<String, LanguageRuleMetadata>,
}

impl RulepackMetadata {
    /// Apply pack-owned defaults to one parsed rule. This is the single
    /// inheritance path used by production loading and focused matcher tests;
    /// callers never need to reproduce tag/category policy in Rust.
    pub fn apply_rule_defaults(&self, rule: &mut Rule) {
        let language_metadata = self.languages.get(&rule.language);
        rule.package_matching = language_metadata
            .map(|metadata| metadata.package_matching.clone())
            .unwrap_or_default();

        let defaults = match rule.kind {
            RuleKind::Sink => {
                let language_default = rule.tag.as_deref().and_then(|tag| {
                    language_metadata.and_then(|metadata| metadata.sink_tag_semantics.get(tag))
                });
                let global_default = rule
                    .tag
                    .as_deref()
                    .and_then(|tag| self.sink_tag_semantics.get(tag));
                let category_default = rule
                    .category
                    .as_deref()
                    .and_then(|category| self.sink_category_semantics.get(category));
                [language_default, global_default, category_default]
            }
            RuleKind::Sanitizer => [
                None,
                rule.tag
                    .as_deref()
                    .and_then(|tag| self.sanitizer_tag_semantics.get(tag)),
                None,
            ],
            RuleKind::Source | RuleKind::Typing => [None, None, None],
        };

        for default in defaults.into_iter().flatten() {
            rule.analysis_semantics
                .get_or_insert_with(AnalysisSemantics::default)
                .inherit_missing(default);
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityProfileMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_tests: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_paths: Vec<String>,
}

impl SecurityProfileMetadata {
    fn merge_overriding(&mut self, incoming: Self) {
        if incoming.trust.is_some() {
            self.trust = incoming.trust;
        }
        if incoming.severity.is_some() {
            self.severity = incoming.severity;
        }
        if incoming.context.is_some() {
            self.context = incoming.context;
        }
        if incoming.exclude_tests.is_some() {
            self.exclude_tests = incoming.exclude_tests;
        }
        if !incoming.exclude_paths.is_empty() {
            self.exclude_paths = incoming.exclude_paths;
        }
    }
}

/// Adapter-visible package spelling rules for one language ecosystem.
/// Shared matching applies these operations generically and never switches on
/// a language id, package-manager convention, or provider spelling.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageMatchSemantics {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strip_import_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strip_import_suffixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub package_separators: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_qualifier_from_package_tail: Option<PackageTailBindingSemantics>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageTailBindingSemantics {
    pub package_separator: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_separators: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LanguageRuleMetadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_applicable_sink_families: Vec<String>,
    /// Exact names or one-asterisk basename patterns for dependency metadata
    /// files (for example `requirements*.txt` or `*.csproj`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependency_manifest_patterns: Vec<String>,
    #[serde(default)]
    pub normalize_hyphen_to_underscore: bool,
    /// Manifest distribution name -> adapter-visible import/package aliases.
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub package_aliases: AHashMap<String, Vec<String>>,
    /// Exact import/package spelling semantics emitted by this language's
    /// adapter. These values are copied onto loaded rules for the generic
    /// package gate; they are not interpreted as security findings.
    #[serde(default)]
    pub package_matching: PackageMatchSemantics,
    /// Defaults inherited by sink rules with the matching tag. Individual
    /// rule fields override these values.
    #[serde(default, skip_serializing_if = "map_is_empty")]
    pub sink_tag_semantics: AHashMap<String, AnalysisSemantics>,
}

impl LanguageRuleMetadata {
    fn merge_overriding(&mut self, incoming: Self) {
        if !incoming.not_applicable_sink_families.is_empty() {
            self.not_applicable_sink_families = incoming.not_applicable_sink_families;
        }
        if !incoming.dependency_manifest_patterns.is_empty() {
            self.dependency_manifest_patterns = incoming.dependency_manifest_patterns;
        }
        if incoming.normalize_hyphen_to_underscore {
            self.normalize_hyphen_to_underscore = true;
        }
        self.package_aliases.extend(incoming.package_aliases);
        if !incoming.package_matching.strip_import_prefixes.is_empty() {
            self.package_matching.strip_import_prefixes = incoming.package_matching.strip_import_prefixes;
        }
        if !incoming.package_matching.strip_import_suffixes.is_empty() {
            self.package_matching.strip_import_suffixes = incoming.package_matching.strip_import_suffixes;
        }
        if !incoming.package_matching.package_separators.is_empty() {
            self.package_matching.package_separators = incoming.package_matching.package_separators;
        }
        if incoming
            .package_matching
            .call_qualifier_from_package_tail
            .is_some()
        {
            self.package_matching.call_qualifier_from_package_tail =
                incoming.package_matching.call_qualifier_from_package_tail;
        }
        merge_analysis_semantics_map(&mut self.sink_tag_semantics, incoming.sink_tag_semantics);
    }
}

fn map_is_empty<K, V>(map: &AHashMap<K, V>) -> bool {
    map.is_empty()
}

fn merge_analysis_semantics_map(
    target: &mut AHashMap<String, AnalysisSemantics>,
    incoming: AHashMap<String, AnalysisSemantics>,
) {
    for (tag, semantics) in incoming {
        if let Some(existing) = target.get_mut(&tag) {
            existing.merge_overriding(semantics);
        } else {
            target.insert(tag, semantics);
        }
    }
}

impl LanguagePack {
    #[must_use]
    pub fn all_rules(&self) -> Vec<&Rule> {
        self.sources
            .iter()
            .chain(self.sinks.iter())
            .chain(self.sanitizers.iter())
            .chain(self.typing.iter())
            .collect()
    }
}

/// The top-level pack — one entry per `langs/<lang>` directory found.
///
/// **Mutation invariant**: any code that pushes to / removes from
/// `packs` (or any nested `LanguagePack` rule vector) MUST clear
/// the lazy `by_id` and compiled receiver-mutation caches. The
/// `pub` field is preserved for ergonomic read access; mutation
/// goes through `merge_overriding` (or any future helper) which
/// resets the cache. External callers performing in-place mutation
/// without clearing the caches will get stale semantic results.
#[derive(Debug)]
pub struct Rulepack {
    pub packs: AHashMap<String, LanguagePack>,
    pub root: PathBuf,
    pub metadata: RulepackMetadata,
    /// Lazy `id → (language, kind, index)` lookup. Built once on
    /// the first `find_rule_by_id` call so hot rendering loops
    /// (`make_finding`, `combine_findings_by_source_flow`,
    /// `synth_summary`) drop from O(N) per call to O(1) without
    /// changing the public API.
    ///
    /// Rule ids encode the language prefix (`python.cmdi.os_system`)
    /// so cross-language collisions don't happen in practice — but
    /// the lookup is still cross-language: two rules sharing an id
    /// would silently overwrite, with the LAST inserted winning.
    /// `find_duplicate_ids_across_pack` locks this in at load time.
    by_id: std::sync::OnceLock<AHashMap<String, (String, RuleKindBucket, usize)>>,
    /// Full enabled-rule content fingerprint used by taint graph cache
    /// keys. Built lazily because broad conformance runs invoke taint
    /// analysis many times against the same immutable pack.
    pub(crate) taint_graph_rule_content_fingerprint: std::sync::OnceLock<u64>,
    /// Per-language receiver-mutating call targets compiled from
    /// `taint_receiver_from_args`. Guard proofs query this hot path per
    /// finding, so rules are indexed once instead of rescanned repeatedly.
    receiver_mutation_targets: std::sync::OnceLock<AHashMap<String, Vec<crate::rule::RuleTarget>>>,
}

impl Default for Rulepack {
    fn default() -> Self {
        Self {
            packs: AHashMap::new(),
            root: PathBuf::new(),
            metadata: RulepackMetadata::default(),
            by_id: std::sync::OnceLock::new(),
            taint_graph_rule_content_fingerprint: std::sync::OnceLock::new(),
            receiver_mutation_targets: std::sync::OnceLock::new(),
        }
    }
}

/// Internal locator used by `Rulepack::by_id`. Tracks which of the
/// three per-language rule vectors the cached index points at.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RuleKindBucket {
    Source,
    Sink,
    Sanitizer,
    Typing,
}

impl Clone for Rulepack {
    fn clone(&self) -> Self {
        // Don't clone the lazy lookup: the cloned pack will rebuild
        // it on first access. `OnceLock` is intentionally not
        // `Clone` for this reason.
        Self {
            packs: self.packs.clone(),
            root: self.root.clone(),
            metadata: self.metadata.clone(),
            by_id: std::sync::OnceLock::new(),
            taint_graph_rule_content_fingerprint: std::sync::OnceLock::new(),
            receiver_mutation_targets: std::sync::OnceLock::new(),
        }
    }
}

impl Rulepack {
    #[must_use]
    pub fn normalized_sink_family<'a>(&'a self, family: &'a str) -> &'a str {
        self.metadata
            .sink_family_aliases
            .get(family)
            .map(String::as_str)
            .unwrap_or(family)
    }

    fn apply_metadata_defaults(&mut self) {
        let metadata = self.metadata.clone();
        for pack in self.packs.values_mut() {
            for rule in pack
                .sinks
                .iter_mut()
                .chain(pack.sanitizers.iter_mut())
                .chain(pack.sources.iter_mut())
                .chain(pack.typing.iter_mut())
            {
                metadata.apply_rule_defaults(rule);
            }
        }
    }

    /// Every rule in every language, for CLI filters that aren't scoped.
    #[must_use]
    pub fn all_rules(&self) -> Vec<&Rule> {
        let mut all = Vec::new();
        for pack in self.packs.values() {
            all.extend(pack.all_rules());
        }
        all
    }

    /// Rulepack-owned call targets whose arguments mutate their receiver.
    /// Built lazily and retained as an immutable semantic index for the life
    /// of this pack.
    pub(crate) fn receiver_mutation_targets(&self, language: &str) -> &[crate::rule::RuleTarget] {
        self.receiver_mutation_targets
            .get_or_init(|| {
                self.packs
                    .iter()
                    .map(|(language, pack)| {
                        let targets = pack
                            .sinks
                            .iter()
                            .chain(&pack.typing)
                            .filter(|rule| {
                                rule.enabled
                                    && rule
                                        .taint_semantics
                                        .as_ref()
                                        .is_some_and(|semantics| semantics.taint_receiver_from_args)
                            })
                            .filter_map(|rule| rule.match_spec.callee.clone())
                            .collect();
                        (language.clone(), targets)
                    })
                    .collect()
            })
            .get(language)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// O(1) rule-id lookup. The first call builds a flat
    /// `id → (language, bucket, index)` index; subsequent calls hit the
    /// cached map. Hot-path callers like `make_finding` and
    /// `combine_findings_by_source_flow` would otherwise pay O(N) per
    /// lookup.
    #[must_use]
    pub fn find_rule_by_id(&self, id: &str) -> Option<&Rule> {
        let index = self.by_id.get_or_init(|| {
            let mut map: AHashMap<String, (String, RuleKindBucket, usize)> = AHashMap::new();
            for (language, pack) in &self.packs {
                for (idx, rule) in pack.sources.iter().enumerate() {
                    map.insert(rule.id.clone(), (language.clone(), RuleKindBucket::Source, idx));
                }
                for (idx, rule) in pack.sinks.iter().enumerate() {
                    map.insert(rule.id.clone(), (language.clone(), RuleKindBucket::Sink, idx));
                }
                for (idx, rule) in pack.sanitizers.iter().enumerate() {
                    map.insert(
                        rule.id.clone(),
                        (language.clone(), RuleKindBucket::Sanitizer, idx),
                    );
                }
                for (idx, rule) in pack.typing.iter().enumerate() {
                    map.insert(rule.id.clone(), (language.clone(), RuleKindBucket::Typing, idx));
                }
            }
            map
        });
        let (language, bucket, idx) = index.get(id)?;
        let pack = self.packs.get(language)?;
        match bucket {
            RuleKindBucket::Source => pack.sources.get(*idx),
            RuleKindBucket::Sink => pack.sinks.get(*idx),
            RuleKindBucket::Sanitizer => pack.sanitizers.get(*idx),
            RuleKindBucket::Typing => pack.typing.get(*idx),
        }
    }

    /// Every language present in the pack, sorted for deterministic
    /// rendering.
    #[must_use]
    pub fn languages(&self) -> Vec<&str> {
        let mut languages: Vec<&str> = self.packs.keys().map(String::as_str).collect();
        languages.sort_unstable();
        languages
    }

    /// Merge `overlay` into `self`, with overlay rules taking
    /// precedence on id conflict. Returns the ids that were
    /// overridden so the caller can warn the user. Used to layer a
    /// project-local pack (`<ws>/.bonsai/rules/`) on top of the
    /// shipped global pack — see [`load_workspace_local_rules`] and
    /// `docs/pattern-guide.mdx`.
    pub fn merge_overriding(&mut self, overlay: Rulepack) -> Vec<String> {
        let mut overridden = Vec::new();
        if !overlay.metadata.canonical_sink_families.is_empty() {
            self.metadata.canonical_sink_families = overlay.metadata.canonical_sink_families.clone();
        }
        self.metadata
            .sink_family_short_labels
            .extend(overlay.metadata.sink_family_short_labels);
        self.metadata
            .sink_family_aliases
            .extend(overlay.metadata.sink_family_aliases);
        self.metadata
            .sanitizer_credits
            .extend(overlay.metadata.sanitizer_credits);
        for (name, incoming) in overlay.metadata.profiles {
            self.metadata
                .profiles
                .entry(name)
                .or_default()
                .merge_overriding(incoming);
        }
        if !overlay.metadata.test_path_patterns.is_empty() {
            self.metadata.test_path_patterns = overlay.metadata.test_path_patterns;
        }
        merge_analysis_semantics_map(
            &mut self.metadata.sink_tag_semantics,
            overlay.metadata.sink_tag_semantics,
        );
        merge_analysis_semantics_map(
            &mut self.metadata.sink_category_semantics,
            overlay.metadata.sink_category_semantics,
        );
        merge_analysis_semantics_map(
            &mut self.metadata.sanitizer_tag_semantics,
            overlay.metadata.sanitizer_tag_semantics,
        );
        for (language, incoming) in overlay.metadata.languages {
            self.metadata
                .languages
                .entry(language)
                .or_default()
                .merge_overriding(incoming);
        }
        for (language, overlay_pack) in overlay.packs {
            let target = self
                .packs
                .entry(language.clone())
                .or_insert_with(|| LanguagePack {
                    language: language.clone(),
                    ..Default::default()
                });
            for rule in overlay_pack.sources {
                replace_or_push(&mut target.sources, rule, &mut overridden);
            }
            for rule in overlay_pack.sinks {
                replace_or_push(&mut target.sinks, rule, &mut overridden);
            }
            for rule in overlay_pack.sanitizers {
                replace_or_push(&mut target.sanitizers, rule, &mut overridden);
            }
            for rule in overlay_pack.typing {
                replace_or_push(&mut target.typing, rule, &mut overridden);
            }
        }
        overridden.sort();
        overridden.dedup();
        // Reset the lazy `id → locator` cache so a future
        // `find_rule_by_id` rebuilds against the merged set.
        self.by_id = std::sync::OnceLock::new();
        self.receiver_mutation_targets = std::sync::OnceLock::new();
        self.apply_metadata_defaults();
        overridden
    }
}

/// In-place merge of `incoming` into `bucket`: if a rule with the same
/// id already exists, replace it (and record the id in `overridden`);
/// otherwise append. Powers `merge_overriding`'s last-write-wins
/// semantics for project-local overlay rules.
fn replace_or_push(bucket: &mut Vec<Rule>, incoming: Rule, overridden: &mut Vec<String>) {
    if let Some(slot) = bucket.iter_mut().find(|rule| rule.id == incoming.id) {
        overridden.push(incoming.id.clone());
        *slot = incoming;
    } else {
        bucket.push(incoming);
    }
}

/// Load the workspace-local rule overlay from
/// `<workspace>/.bonsai/rules/`. Returns `Ok(None)` if the directory
/// doesn't exist (the common case — projects rarely ship overrides).
/// Otherwise loads using the same layout rules as
/// [`load_rulepack`]. Project-local rules let teams encode their own
/// invariants (e.g. `@requires_admin`, `verify_csrf_token()`) as
/// sanitizers without polluting the shipped global pack.
pub fn load_workspace_local_rules(workspace: &Path) -> Result<Option<Rulepack>, LoadError> {
    // Local rules are user-authored project configuration, not disposable
    // analysis cache. Keep this explicit repository path separate from the
    // OS cache directory returned by `workspace_bonsai_dir`.
    let local_root = workspace.join(".bonsai").join("rules");
    if !local_root.exists() {
        return Ok(None);
    }
    if !local_root.is_dir() {
        return Err(LoadError::MissingRoot(local_root));
    }
    // Local layout: <ws>/.bonsai/rules/<lang>/{sources,sinks,sanitizers}/*.yml.
    // The `langs/` wrapper from the global pack is dropped so the
    // user-visible directory is one level shallower.
    let mut pack = Rulepack {
        packs: AHashMap::new(),
        root: local_root.clone(),
        metadata: load_rulepack_metadata(&local_root)?,
        by_id: std::sync::OnceLock::new(),
        taint_graph_rule_content_fingerprint: std::sync::OnceLock::new(),
        receiver_mutation_targets: std::sync::OnceLock::new(),
    };
    let entries = read_dir(&local_root)?;
    for entry in entries {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let lang = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        // Reserve `sources/` / `sinks/` / `sanitizers/` for the
        // flat-layout pass below — they aren't languages.
        if matches!(lang.as_str(), "sources" | "sinks" | "sanitizers" | "typing") {
            continue;
        }
        let mut lp = LanguagePack {
            language: lang.clone(),
            ..Default::default()
        };
        for kind in [
            RuleKind::Source,
            RuleKind::Sink,
            RuleKind::Sanitizer,
            RuleKind::Typing,
        ] {
            let dir = path.join(kind.dir_name());
            if !dir.exists() {
                continue;
            }
            let files = read_dir(&dir)?;
            for f in files {
                let fpath = f.path();
                let ext = fpath.extension().and_then(|e| e.to_str());
                if ext != Some("yml") && ext != Some("yaml") {
                    continue;
                }
                let rules = parse_rule_file(&fpath, kind, Some(&lang))?;
                match kind {
                    RuleKind::Source => lp.sources.extend(rules),
                    RuleKind::Sink => lp.sinks.extend(rules),
                    RuleKind::Sanitizer => lp.sanitizers.extend(rules),
                    RuleKind::Typing => lp.typing.extend(rules),
                }
            }
        }
        pack.packs.insert(lang, lp);
    }
    // Flat-layout overlay: <ws>/.bonsai/rules/{sources,sinks,sanitizers}/*.yml.
    // YAML must declare `language:`. Same routing as `load_rulepack`.
    load_flat_layout_into(&local_root, &mut pack)?;
    pack.apply_metadata_defaults();
    // Overlay packs feed `merge_overriding`, which legitimately
    // last-writes on collision against the global pack — but two
    // overlay rules sharing an id are almost certainly a mistake.
    // Same flat-namespace check as `load_rulepack`.
    check_cross_language_duplicate_ids(&pack)?;
    Ok(Some(pack))
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("rulepack root `{0}` does not exist or is not a directory")]
    MissingRoot(PathBuf),
    #[error("failed to read `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("duplicate rule id `{id}` — seen at `{first}` and `{second}`")]
    DuplicateId {
        id: String,
        first: String,
        second: String,
    },
    #[error("rule `{id}` in `{path}`: match.kind `{kind:?}` requires `callee`, got empty target")]
    MissingCallee {
        id: String,
        path: String,
        kind: MatchKind,
    },
    #[error("rule `{id}` in `{path}`: match.kind `{kind:?}` requires `target`, got empty target")]
    MissingTarget {
        id: String,
        path: String,
        kind: MatchKind,
    },
    #[error("rule `{id}` in `{path}`: `call_kind_in` is only valid for call-shaped matches, not `{kind:?}`")]
    InvalidCallKindConstraint {
        id: String,
        path: String,
        kind: MatchKind,
    },
    #[error("rule `{id}` in `{path}`: invalid typing declaration: {detail}")]
    InvalidTypingDeclaration {
        id: String,
        path: String,
        detail: &'static str,
    },
    #[error(
        "rule `{id}` in `{path}`: YAML `language: {yaml}` does not match directory-derived language `{dir}`"
    )]
    LanguageMismatch {
        id: String,
        path: String,
        yaml: String,
        dir: String,
    },
    #[error("rule `{id}` in `{path}`: flat-layout rule must declare `language:` in YAML (no `langs/<lang>/` wrapper)")]
    MissingLanguage { id: String, path: String },
    #[error("rule `{id}` in `{path}`: match regex `{regex}` is a tautology (matches every site); narrow it or drop the field")]
    TautologicalRegex { id: String, path: String, regex: String },
}

/// Parse a rulepack root.
///
/// Two layouts are supported and may coexist within the same root:
///
/// 1. **Per-language directories** (canonical, used by the bundled pack):
///    ```text
///    <root>/langs/<lang>/{sources,sinks,sanitizers}/*.yml
///    ```
///    Each rule's `language` is taken from the directory wrapper.
///    A YAML `language:` field is allowed but must match the directory.
///
/// 2. **Flat layout** (for custom rulepack projects):
///    ```text
///    <root>/{sources,sinks,sanitizers}/*.yml
///    ```
///    Each rule **must** declare `language:` in YAML. Loaded rules are
///    routed into the language pack their YAML names.
///
/// Missing `sources/` / `sinks/` / `sanitizers/` directories for a language
/// are fine — the language is loaded with empty buckets. A root with
/// neither `langs/` nor any flat-layout family directories is an empty
/// (but valid) rulepack.
pub fn load_rulepack(root: &Path) -> Result<Rulepack, LoadError> {
    if !root.exists() || !root.is_dir() {
        return Err(LoadError::MissingRoot(root.to_path_buf()));
    }
    let mut pack = Rulepack {
        packs: AHashMap::new(),
        root: root.to_path_buf(),
        metadata: load_rulepack_metadata(root)?,
        by_id: std::sync::OnceLock::new(),
        taint_graph_rule_content_fingerprint: std::sync::OnceLock::new(),
        receiver_mutation_targets: std::sync::OnceLock::new(),
    };
    let langs_dir = root.join("langs");
    if langs_dir.exists() {
        let entries = read_dir(&langs_dir)?;
        for entry in entries {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let lang = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let lp = pack.packs.entry(lang.clone()).or_insert_with(|| LanguagePack {
                language: lang.clone(),
                ..Default::default()
            });
            for kind in [
                RuleKind::Source,
                RuleKind::Sink,
                RuleKind::Sanitizer,
                RuleKind::Typing,
            ] {
                let dir = path.join(kind.dir_name());
                if !dir.exists() {
                    continue;
                }
                let files = read_dir(&dir)?;
                for f in files {
                    let fpath = f.path();
                    if fpath.extension().and_then(|e| e.to_str()) != Some("yml")
                        && fpath.extension().and_then(|e| e.to_str()) != Some("yaml")
                    {
                        continue;
                    }
                    let rules = parse_rule_file(&fpath, kind, Some(&lang))?;
                    match kind {
                        RuleKind::Source => lp.sources.extend(rules),
                        RuleKind::Sink => lp.sinks.extend(rules),
                        RuleKind::Sanitizer => lp.sanitizers.extend(rules),
                        RuleKind::Typing => lp.typing.extend(rules),
                    }
                }
            }
        }
    }
    // Flat layout: `<root>/{sources,sinks,sanitizers}/*.yml`. Rules
    // declare `language:` in YAML and are routed into the matching
    // language pack (creating a new bucket if needed).
    load_flat_layout_into(root, &mut pack)?;
    pack.apply_metadata_defaults();
    // Duplicate-id check WITHIN each language, across all three buckets.
    for lp in pack.packs.values() {
        let mut seen: AHashMap<String, String> = AHashMap::new();
        for rule in lp
            .sources
            .iter()
            .chain(lp.sinks.iter())
            .chain(lp.sanitizers.iter())
        {
            if let Some(prev) = seen.get(&rule.id) {
                return Err(LoadError::DuplicateId {
                    id: rule.id.clone(),
                    first: prev.clone(),
                    second: rule.source_path.clone(),
                });
            }
            seen.insert(rule.id.clone(), rule.source_path.clone());
        }
    }
    // Cross-language duplicate-id check. The `by_id` lookup is
    // workspace-flat: two rules sharing an id (even across
    // languages) would otherwise silently overwrite at lookup
    // time. Convention is `<lang>.<family>.<name>` so collisions
    // require deliberate misnaming, but lock it in at load time.
    check_cross_language_duplicate_ids(&pack)?;
    Ok(pack)
}

/// Return the canonical files that define a rulepack's security semantics.
///
/// Package scaffolding, documentation, VCS metadata, and other files beside a
/// pack do not affect matching and therefore must not invalidate persisted
/// analysis. The inventory mirrors [`load_rulepack`]: the selected metadata
/// file, optional `VERSION`, canonical per-language rule buckets, and flat
/// custom-pack rule buckets. Paths are sorted and deduplicated so cache
/// fingerprints are deterministic on every filesystem.
pub fn rulepack_semantic_files(root: &Path) -> Result<Vec<PathBuf>, LoadError> {
    if !root.exists() || !root.is_dir() {
        return Err(LoadError::MissingRoot(root.to_path_buf()));
    }

    let mut files = Vec::new();
    let version = root.join("VERSION");
    if version.is_file() {
        files.push(version);
    }
    let metadata_yml = root.join("metadata.yml");
    let metadata_yaml = root.join("metadata.yaml");
    if metadata_yml.is_file() {
        files.push(metadata_yml);
    } else if metadata_yaml.is_file() {
        files.push(metadata_yaml);
    }

    let kinds = [
        RuleKind::Source,
        RuleKind::Sink,
        RuleKind::Sanitizer,
        RuleKind::Typing,
    ];
    let langs_dir = root.join("langs");
    if langs_dir.exists() {
        for language in read_dir(&langs_dir)? {
            let language_dir = language.path();
            if !language_dir.is_dir() {
                continue;
            }
            for kind in kinds {
                collect_rule_yaml_files(&language_dir.join(kind.dir_name()), &mut files)?;
            }
        }
    }
    for kind in kinds {
        collect_rule_yaml_files(&root.join(kind.dir_name()), &mut files)?;
    }

    files.sort();
    files.dedup();
    Ok(files)
}

fn collect_rule_yaml_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), LoadError> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in read_dir(dir)? {
        let path = entry.path();
        if matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("yml" | "yaml")
        ) {
            files.push(path);
        }
    }
    Ok(())
}

fn load_rulepack_metadata(root: &Path) -> Result<RulepackMetadata, LoadError> {
    let yaml = root.join("metadata.yml");
    let yaml_alt = root.join("metadata.yaml");
    let path = if yaml.exists() {
        yaml
    } else if yaml_alt.exists() {
        yaml_alt
    } else {
        return Ok(RulepackMetadata::default());
    };
    let text = std::fs::read_to_string(&path).map_err(|source| LoadError::Io {
        path: path.clone(),
        source,
    })?;
    serde_yaml::from_str(&text).map_err(|source| LoadError::Parse { path, source })
}

/// Walk `<root>/{sources,sinks,sanitizers}/*.yml` and add every rule
/// found to the matching language pack within `pack`. YAML must
/// declare `language:` for each rule (enforced by `parse_rule_file`).
fn load_flat_layout_into(root: &Path, pack: &mut Rulepack) -> Result<(), LoadError> {
    for kind in [
        RuleKind::Source,
        RuleKind::Sink,
        RuleKind::Sanitizer,
        RuleKind::Typing,
    ] {
        let dir = root.join(kind.dir_name());
        if !dir.exists() {
            continue;
        }
        let files = read_dir(&dir)?;
        for f in files {
            let fpath = f.path();
            let ext = fpath.extension().and_then(|e| e.to_str());
            if ext != Some("yml") && ext != Some("yaml") {
                continue;
            }
            let rules = parse_rule_file(&fpath, kind, None)?;
            for r in rules {
                let lp = pack
                    .packs
                    .entry(r.language.clone())
                    .or_insert_with(|| LanguagePack {
                        language: r.language.clone(),
                        ..Default::default()
                    });
                match kind {
                    RuleKind::Source => lp.sources.push(r),
                    RuleKind::Sink => lp.sinks.push(r),
                    RuleKind::Sanitizer => lp.sanitizers.push(r),
                    RuleKind::Typing => lp.typing.push(r),
                }
            }
        }
    }
    Ok(())
}

/// Validate that no two rules in `pack` share an `id` across the
/// flat (language, kind) namespace. Sorted scan so the
/// `LoadError::DuplicateId` `first`/`second` paths are
/// deterministic across runs (the underlying `AHashMap` iteration
/// order is unstable).
fn check_cross_language_duplicate_ids(pack: &Rulepack) -> Result<(), LoadError> {
    let mut all: Vec<&Rule> = pack.all_rules();
    all.sort_by(|a, b| {
        (a.language.as_str(), a.source_path.as_str(), a.id.as_str()).cmp(&(
            b.language.as_str(),
            b.source_path.as_str(),
            b.id.as_str(),
        ))
    });
    let mut seen: AHashMap<String, String> = AHashMap::new();
    for rule in all {
        if let Some(prev) = seen.get(&rule.id) {
            return Err(LoadError::DuplicateId {
                id: rule.id.clone(),
                first: prev.clone(),
                second: rule.source_path.clone(),
            });
        }
        seen.insert(rule.id.clone(), rule.source_path.clone());
    }
    Ok(())
}

/// Read a directory and return its entries sorted by filename.
/// Sorting matters because rule load order affects diagnostic
/// output ordering, which our tests assert against verbatim.
fn read_dir(path: &Path) -> Result<Vec<std::fs::DirEntry>, LoadError> {
    let read_dir_iter = std::fs::read_dir(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut entries = Vec::new();
    for entry in read_dir_iter {
        let entry = entry.map_err(|source| LoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        entries.push(entry);
    }
    // Deterministic load order — important for stable diagnostic output.
    entries.sort_by_key(std::fs::DirEntry::file_name);
    Ok(entries)
}

/// Parse one YAML rule file.
///
/// `dir_language` is `Some(<lang>)` when the file lives under a
/// `langs/<lang>/` wrapper (the canonical layout) and `None` for
/// flat-layout custom packs where YAML must declare `language:`.
///
/// Resolution rules:
///   * dir + YAML both present and equal → ok, stamp lang.
///   * dir + YAML both present and different → `LanguageMismatch`.
///   * dir present, YAML empty → ok, stamp dir.
///   * dir absent, YAML present → ok, use YAML's value.
///   * dir absent, YAML empty → `MissingLanguage`.
fn parse_rule_file(path: &Path, kind: RuleKind, dir_language: Option<&str>) -> Result<Vec<Rule>, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let raw: Vec<Rule> = serde_yaml::from_str(&text).map_err(|source| LoadError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    let mut out = Vec::with_capacity(raw.len());
    for mut r in raw {
        r.kind = kind;
        r.source_path = path.display().to_string();
        let yaml_lang = std::mem::take(&mut r.language);
        let resolved = match (dir_language, yaml_lang.as_str()) {
            (Some(dir), "") => dir.to_string(),
            (Some(dir), yaml) if dir == yaml => dir.to_string(),
            (Some(dir), yaml) => {
                return Err(LoadError::LanguageMismatch {
                    id: r.id.clone(),
                    path: r.source_path.clone(),
                    yaml: yaml.to_string(),
                    dir: dir.to_string(),
                });
            }
            (None, "") => {
                return Err(LoadError::MissingLanguage {
                    id: r.id.clone(),
                    path: r.source_path.clone(),
                });
            }
            (None, yaml) => yaml.to_string(),
        };
        r.language = resolved;
        validate_rule(&r)?;
        out.push(r);
    }
    Ok(out)
}

/// Enforce the schema rules on a freshly-parsed rule: required fields
/// per match kind, no tautological regexes that would fire on every
/// site.
fn validate_rule(rule: &Rule) -> Result<(), LoadError> {
    let typing_error = |detail| LoadError::InvalidTypingDeclaration {
        id: rule.id.clone(),
        path: rule.source_path.clone(),
        detail,
    };
    if rule.match_spec.kind == MatchKind::Type && rule.kind != RuleKind::Typing {
        return Err(typing_error("match.kind type is valid only in typing rules"));
    }
    if (!rule.callback_param_types.is_empty() || rule.callback_arg_index.is_some())
        && rule.kind != RuleKind::Typing
    {
        return Err(typing_error(
            "callback_param_types and callback_arg_index are valid only in typing rules",
        ));
    }
    if rule.kind == RuleKind::Typing && !rule.callback_param_types.is_empty() {
        if rule.callback_param_types.iter().any(Vec::is_empty) {
            return Err(typing_error(
                "every callback_param_types entry must declare at least one exact type alias",
            ));
        }
        match rule.match_spec.kind {
            MatchKind::Call if rule.callback_arg_index.is_some() => {}
            MatchKind::Type if rule.callback_arg_index.is_none() => {}
            MatchKind::Call => {
                return Err(typing_error("call callback typing requires callback_arg_index"));
            }
            MatchKind::Type => {
                return Err(typing_error(
                    "type callback typing must not declare callback_arg_index",
                ));
            }
            _ => {
                return Err(typing_error(
                    "callback_param_types requires match.kind call or type",
                ));
            }
        }
    } else if rule.callback_arg_index.is_some() {
        return Err(typing_error("callback_arg_index requires callback_param_types"));
    }
    if rule.kind == RuleKind::Typing
        && rule.match_spec.kind == MatchKind::Type
        && rule.callback_param_types.is_empty()
    {
        return Err(typing_error("match.kind type requires callback_param_types"));
    }
    if let Some(transition) = &rule.lifecycle_transition {
        if rule.kind != RuleKind::Typing {
            return Err(typing_error("lifecycle_transition is valid only in typing rules"));
        }
        if rule.match_spec.kind != MatchKind::Call {
            return Err(typing_error("lifecycle_transition requires match.kind call"));
        }
        if transition.state.trim().is_empty() {
            return Err(typing_error("lifecycle_transition.state must be non-empty"));
        }
    }
    match rule.match_spec.kind {
        MatchKind::Call | MatchKind::New | MatchKind::Missing => {
            // Call-shaped rules (including Missing — inverse-match on an
            // expected callee) need a callee; an empty target is unusable.
            let callee = rule
                .match_spec
                .callee
                .as_ref()
                .filter(|target| !target.is_empty());
            if callee.is_none() {
                return Err(LoadError::MissingCallee {
                    id: rule.id.clone(),
                    path: rule.source_path.clone(),
                    kind: rule.match_spec.kind,
                });
            }
        }
        MatchKind::Read | MatchKind::Write | MatchKind::Param | MatchKind::Type => {
            // Place-shaped rules need a target; an empty target is unusable.
            let target = rule
                .match_spec
                .target
                .as_ref()
                .filter(|target| !target.is_empty());
            if target.is_none() {
                return Err(LoadError::MissingTarget {
                    id: rule.id.clone(),
                    path: rule.source_path.clone(),
                    kind: rule.match_spec.kind,
                });
            }
        }
        MatchKind::Return => {
            // A return rule without a target matches every compiler-lowered
            // return expression. Optional name/regex targets narrow the
            // returned expression; no pseudo-callee spelling is required.
        }
    }
    // Loader lint: any rule whose `target.regex` is a tautology
    // (`.*`, `.+`, `^.*$`, ...) matches every site of the chosen
    // `kind` — this fires on every parameter / every read / every
    // call, regardless of `enabled:`. The `enabled: false` exemption
    // doesn't apply here because such a rule is unusable anywhere
    // it gets enabled. Reject at load time.
    if let Some(rule_target) = rule
        .match_spec
        .callee
        .as_ref()
        .or(rule.match_spec.target.as_ref())
    {
        if !rule_target.call_kind_in.is_empty()
            && !matches!(rule.match_spec.kind, MatchKind::Call | MatchKind::Missing)
        {
            return Err(LoadError::InvalidCallKindConstraint {
                id: rule.id.clone(),
                path: rule.source_path.clone(),
                kind: rule.match_spec.kind,
            });
        }
        if let Some(regex) = rule_target.regex.as_deref() {
            if is_tautological_regex(regex) {
                return Err(LoadError::TautologicalRegex {
                    id: rule.id.clone(),
                    path: rule.source_path.clone(),
                    regex: regex.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// True when `regex` matches every string. Catches the common
/// "match everything" footguns (`.*`, `.+`, `^.*$`, `^.+$`,
/// trailing-slash variants, the single-char `.` form).
fn is_tautological_regex(regex: &str) -> bool {
    matches!(
        regex.trim(),
        ".*" | ".+" | "^.*$" | "^.+$" | ".*?" | "^.*?$" | "^.+?$" | "." | "^$" | ""
    )
}

/// Severity-by-name fallback used by the CLI's `--severity` filter.
#[must_use]
pub fn parse_severity(name: &str) -> Option<Severity> {
    match name.to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}
