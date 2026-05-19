//! Rulepack loader — walks a `security-patterns/` directory, validates
//! every rule, and returns a language-keyed [`Rulepack`].
//!
//! Hard rules enforced here:
//!   * `sources/` rules get `kind = Source`, `sinks/` gets `Sink`,
//!     `sanitizers/` gets `Sanitizer`. The `kind` is always
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

use crate::rule::{MatchKind, Rule, RuleKind, Severity};
use ahash::AHashMap;
use bonsai_common::workspace_bonsai_dir;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// A language's loaded rules, partitioned by family.
#[derive(Clone, Debug, Default)]
pub struct LanguagePack {
    pub language: String,
    pub sources: Vec<Rule>,
    pub sinks: Vec<Rule>,
    pub sanitizers: Vec<Rule>,
}

impl LanguagePack {
    #[must_use]
    pub fn all_rules(&self) -> Vec<&Rule> {
        self.sources
            .iter()
            .chain(self.sinks.iter())
            .chain(self.sanitizers.iter())
            .collect()
    }
}

/// The top-level pack — one entry per `langs/<lang>` directory found.
///
/// **Mutation invariant**: any code that pushes to / removes from
/// `packs` (or any nested `LanguagePack` rule vector) MUST clear
/// the lazy `by_id` cache via `self.by_id = OnceLock::new()`. The
/// `pub` field is preserved for ergonomic read access; mutation
/// goes through `merge_overriding` (or any future helper) which
/// resets the cache. External callers performing in-place mutation
/// without clearing the cache will get stale lookup results.
#[derive(Debug)]
pub struct Rulepack {
    pub packs: AHashMap<String, LanguagePack>,
    pub root: PathBuf,
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
}

impl Default for Rulepack {
    fn default() -> Self {
        Self {
            packs: AHashMap::new(),
            root: PathBuf::new(),
            by_id: std::sync::OnceLock::new(),
            taint_graph_rule_content_fingerprint: std::sync::OnceLock::new(),
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
}

impl Clone for Rulepack {
    fn clone(&self) -> Self {
        // Don't clone the lazy lookup: the cloned pack will rebuild
        // it on first access. `OnceLock` is intentionally not
        // `Clone` for this reason.
        Self {
            packs: self.packs.clone(),
            root: self.root.clone(),
            by_id: std::sync::OnceLock::new(),
            taint_graph_rule_content_fingerprint: std::sync::OnceLock::new(),
        }
    }
}

impl Rulepack {
    /// Every rule in every language, for CLI filters that aren't scoped.
    #[must_use]
    pub fn all_rules(&self) -> Vec<&Rule> {
        let mut all = Vec::new();
        for pack in self.packs.values() {
            all.extend(pack.all_rules());
        }
        all
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
            }
            map
        });
        let (language, bucket, idx) = index.get(id)?;
        let pack = self.packs.get(language)?;
        match bucket {
            RuleKindBucket::Source => pack.sources.get(*idx),
            RuleKindBucket::Sink => pack.sinks.get(*idx),
            RuleKindBucket::Sanitizer => pack.sanitizers.get(*idx),
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
        }
        overridden.sort();
        overridden.dedup();
        // Reset the lazy `id → locator` cache so a future
        // `find_rule_by_id` rebuilds against the merged set.
        self.by_id = std::sync::OnceLock::new();
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
    let local_root = workspace_bonsai_dir(workspace).join("rules");
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
        by_id: std::sync::OnceLock::new(),
        taint_graph_rule_content_fingerprint: std::sync::OnceLock::new(),
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
        if matches!(lang.as_str(), "sources" | "sinks" | "sanitizers") {
            continue;
        }
        let mut lp = LanguagePack {
            language: lang.clone(),
            ..Default::default()
        };
        for kind in [RuleKind::Source, RuleKind::Sink, RuleKind::Sanitizer] {
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
                }
            }
        }
        pack.packs.insert(lang, lp);
    }
    // Flat-layout overlay: <ws>/.bonsai/rules/{sources,sinks,sanitizers}/*.yml.
    // YAML must declare `language:`. Same routing as `load_rulepack`.
    load_flat_layout_into(&local_root, &mut pack)?;
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
    #[error("rule `{id}` in `{path}`: every match target must set name, attribute, or regex")]
    EmptyTarget { id: String, path: String },
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
        by_id: std::sync::OnceLock::new(),
        taint_graph_rule_content_fingerprint: std::sync::OnceLock::new(),
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
            for kind in [RuleKind::Source, RuleKind::Sink, RuleKind::Sanitizer] {
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
                    }
                }
            }
        }
    }
    // Flat layout: `<root>/{sources,sinks,sanitizers}/*.yml`. Rules
    // declare `language:` in YAML and are routed into the matching
    // language pack (creating a new bucket if needed).
    load_flat_layout_into(root, &mut pack)?;
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

/// Walk `<root>/{sources,sinks,sanitizers}/*.yml` and add every rule
/// found to the matching language pack within `pack`. YAML must
/// declare `language:` for each rule (enforced by `parse_rule_file`).
fn load_flat_layout_into(root: &Path, pack: &mut Rulepack) -> Result<(), LoadError> {
    for kind in [RuleKind::Source, RuleKind::Sink, RuleKind::Sanitizer] {
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
        MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param => {
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
