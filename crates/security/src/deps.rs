//! Dependency / package inventory built from rule metadata + workspace imports.
//!
//! A rule is considered "evident" in the workspace when any of its
//! `imports` / `modules` / `packages` strings appears in:
//!
//! * An import fact emitted by the language adapter's indexer
//!   (via `decl_index.refs` of kind `Import`, or the
//!   `import_index` the workspace computes).
//! * A manifest / lockfile declared under the workspace root whose
//!   basename matches one of the rule's `manifests` / `lockfiles`
//!   entries.
//! * A dependency manifest under the workspace root whose content
//!   names one of the rule's `packages` entries. This catches
//!   first-party scans where the workspace itself is the flagged
//!   package, so the package name appears in `pom.xml`,
//!   `package.json`, `Cargo.toml`, etc. rather than in an import.
//!
//! Output rows unify the three signals so reviewers see WHAT is present
//! and WHY the wrapper flagged it.

use crate::loader::Rulepack;
use crate::rule::{Rule, Severity};
use ahash::{AHashMap, AHashSet};
use bonsai_common::dependency_metadata::{dependency_metadata_dir_skipped, walk_dependency_metadata_files};
use bonsai_workspace::Workspace;
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Debug, Serialize)]
pub struct DependencyRow {
    pub language: String,
    pub key: String,
    /// The rule ids that claimed this dependency — source & sink both.
    pub rule_ids: Vec<String>,
    /// `frameworks` / `packages` / `imports` / `modules` / `manifests` /
    /// `lockfiles` signals that fired, from most- to least-specific.
    pub signals: Vec<String>,
    /// The files that carry matching manifests / lockfiles / imports.
    pub evidence_files: Vec<String>,
    /// Severity of the highest-severity rule that claimed this entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// Unique tags from the claiming rules.
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DependencyInventory {
    pub rows: Vec<DependencyRow>,
}

/// Build the inventory. Scans the workspace root for manifest / lockfile
/// basenames and the workspace index for import / module facts.
pub fn build_inventory(pack: &Rulepack, ws: &Workspace, root: &Path) -> DependencyInventory {
    let manifest_files = scan_manifest_files(root, pack);
    let import_evidence_by_lang = collect_workspace_import_evidence(ws, pack);
    let manifest_package_evidence_by_lang = collect_manifest_package_evidence(pack, &manifest_files);

    let mut by_key: AHashMap<(String, String), DependencyRow> = AHashMap::new();
    for rule in pack.all_rules() {
        if !rule.enabled {
            continue;
        }
        for key in rule_signal_keys(rule) {
            let (signals, evidence) = rule_key_evidence(
                rule,
                &key,
                &manifest_files,
                &import_evidence_by_lang,
                &manifest_package_evidence_by_lang,
            );
            if signals.is_empty() {
                continue;
            }
            let entry = by_key
                .entry((rule.language.clone(), key.clone()))
                .or_insert(DependencyRow {
                    language: rule.language.clone(),
                    key,
                    rule_ids: Vec::new(),
                    signals: Vec::new(),
                    evidence_files: Vec::new(),
                    severity: None,
                    tags: Vec::new(),
                });
            if !entry.rule_ids.contains(&rule.id) {
                entry.rule_ids.push(rule.id.clone());
            }
            for s in signals {
                if !entry.signals.contains(&s) {
                    entry.signals.push(s);
                }
            }
            for e in evidence {
                if !entry.evidence_files.contains(&e) {
                    entry.evidence_files.push(e);
                }
            }
            match (entry.severity, rule.severity) {
                (None, Some(s)) => entry.severity = Some(s),
                (Some(prev), Some(s)) if s > prev => entry.severity = Some(s),
                _ => {}
            }
            if let Some(tag) = &rule.tag {
                if !entry.tags.contains(tag) {
                    entry.tags.push(tag.clone());
                }
            }
        }
    }

    let mut rows: Vec<DependencyRow> = by_key.into_values().collect();
    rows.sort_by(|a, b| (a.language.as_str(), a.key.as_str()).cmp(&(b.language.as_str(), b.key.as_str())));
    DependencyInventory { rows }
}

#[derive(Clone, Debug)]
pub(crate) struct WorkspaceDependencyPackages {
    pub fingerprint: u64,
    pub packages: Arc<AHashSet<String>>,
}

#[derive(Clone, Debug)]
struct WorkspaceDependencyPackageContext {
    fingerprint: u64,
    by_language: AHashMap<String, Arc<AHashSet<String>>>,
}

static WORKSPACE_DEPENDENCY_PACKAGE_CACHE: std::sync::LazyLock<
    parking_lot::RwLock<AHashMap<String, Arc<WorkspaceDependencyPackageContext>>>,
> = std::sync::LazyLock::new(|| parking_lot::RwLock::new(AHashMap::new()));

/// Return package/dependency names declared in workspace-level manifests
/// for `language`.
///
/// Per-file imports are still the strongest evidence used by the matcher,
/// but framework template files often do not contain an import for the
/// runtime package they execute under (Rails ERB / ActionView is the
/// canonical case). This language-scoped manifest context lets package gates
/// accept those real project dependencies without letting one language's
/// manifest satisfy another language's package-scoped rules in a monorepo.
pub(crate) fn workspace_dependency_packages_for_language(
    root: &Path,
    language: &str,
) -> WorkspaceDependencyPackages {
    let root_key = root
        .canonicalize()
        .unwrap_or_else(|_| root.to_path_buf())
        .to_string_lossy()
        .into_owned();
    if let Some(context) = WORKSPACE_DEPENDENCY_PACKAGE_CACHE.read().get(&root_key).cloned() {
        return WorkspaceDependencyPackages {
            fingerprint: context.fingerprint,
            packages: context
                .by_language
                .get(language)
                .cloned()
                .unwrap_or_else(|| Arc::new(AHashSet::new())),
        };
    }

    let context = Arc::new(build_workspace_dependency_package_context(root));
    let mut cache = WORKSPACE_DEPENDENCY_PACKAGE_CACHE.write();
    if cache.len() >= 64 {
        cache.clear();
    }
    let context = cache.entry(root_key).or_insert_with(|| context.clone()).clone();
    WorkspaceDependencyPackages {
        fingerprint: context.fingerprint,
        packages: context
            .by_language
            .get(language)
            .cloned()
            .unwrap_or_else(|| Arc::new(AHashSet::new())),
    }
}

fn build_workspace_dependency_package_context(root: &Path) -> WorkspaceDependencyPackageContext {
    let mut by_language: AHashMap<String, AHashSet<String>> = AHashMap::new();
    let mut fingerprint_parts = Vec::new();
    let _ = walk_dependency_metadata_files(root, |path, rel| {
        let bytes = std::fs::read(path)?;
        fingerprint_parts.push(format!("{rel}:{}", bonsai_hash::fnv1a_bytes64(&bytes)));
        let text = String::from_utf8_lossy(&bytes);
        let packages = dependency_manifest_package_tokens(&text);
        if !packages.is_empty() {
            for language in dependency_manifest_languages(path) {
                let packages = dependency_manifest_packages_for_language(&packages, language);
                by_language
                    .entry((*language).to_string())
                    .or_default()
                    .extend(packages.into_iter());
            }
        }
        Ok(())
    });
    fingerprint_parts.sort();
    let fingerprint = bonsai_hash::fnv1a_names64(&fingerprint_parts);
    let by_language = by_language
        .into_iter()
        .map(|(language, packages)| (language, Arc::new(packages)))
        .collect();
    WorkspaceDependencyPackageContext {
        fingerprint,
        by_language,
    }
}

fn dependency_manifest_languages(path: &Path) -> &'static [&'static str] {
    let basename = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    let lower = basename.to_ascii_lowercase();
    match basename {
        "Gemfile" | "Gemfile.lock" => &["ruby"],
        "package.json"
        | "package-lock.json"
        | "pnpm-lock.yaml"
        | "pnpm-workspace.yaml"
        | "yarn.lock"
        | "bun.lock"
        | "bun.lockb"
        | "deno.json"
        | "deno.jsonc"
        | "deno.lock" => &["javascript", "typescript"],
        "mix.exs" | "mix.lock" => &["elixir"],
        "rebar.config" | "rebar.lock" => &["erlang"],
        "go.mod" | "go.sum" | "go.work" | "go.work.sum" => &["go"],
        "Cargo.toml" | "Cargo.lock" => &["rust"],
        "composer.json" | "composer.lock" => &["php"],
        "pyproject.toml" | "requirements.txt" | "Pipfile" | "Pipfile.lock" | "poetry.lock" | "uv.lock" => {
            &["python"]
        }
        "pom.xml"
        | "build.gradle"
        | "build.gradle.kts"
        | "settings.gradle"
        | "settings.gradle.kts"
        | "gradle.lockfile"
        | "gradle.properties" => &["java", "kotlin", "scala"],
        "Package.swift" | "Package.resolved" | "Cartfile" | "Cartfile.resolved" => &["swift"],
        "Podfile" | "Podfile.lock" => &["objc", "swift"],
        "packages.config" => &["csharp"],
        _ if path_has_extension(&lower, "gemspec") => &["ruby"],
        _ if path_has_extension(&lower, "csproj")
            || path_has_extension(&lower, "fsproj")
            || path_has_extension(&lower, "vbproj")
            || path_has_extension(&lower, "sln")
            || path_has_extension(&lower, "slnx")
            || path_has_extension(&lower, "props")
            || path_has_extension(&lower, "targets") =>
        {
            &["csharp"]
        }
        _ if lower.starts_with("requirements") && path_has_extension(&lower, "txt") => &["python"],
        _ => &[],
    }
}

fn path_has_extension(path: &str, extension: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|actual| actual.eq_ignore_ascii_case(extension))
}

fn dependency_manifest_package_tokens(text: &str) -> AHashSet<String> {
    let mut out = AHashSet::new();
    let mut token = String::new();
    for ch in text.chars() {
        if dependency_package_token_char(ch) {
            token.push(ch);
            continue;
        }
        insert_dependency_package_token(&mut out, &token);
        token.clear();
    }
    insert_dependency_package_token(&mut out, &token);
    out
}

fn dependency_package_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | '@' | ':' | '+')
}

fn insert_dependency_package_token(out: &mut AHashSet<String>, token: &str) {
    let token = token.trim_matches(|ch: char| matches!(ch, '.' | '/' | ':' | '+' | '-' | '_'));
    if token.len() < 2 || !token.chars().any(|ch| ch.is_ascii_alphabetic()) {
        return;
    }
    out.insert(token.to_string());
    let lower = token.to_ascii_lowercase();
    out.insert(lower);
}

fn dependency_manifest_packages_for_language(
    packages: &AHashSet<String>,
    language: &str,
) -> AHashSet<String> {
    let mut out = packages.clone();
    for package in packages {
        insert_dependency_package_aliases(&mut out, language, package);
    }
    out
}

fn insert_dependency_package_aliases(out: &mut AHashSet<String>, language: &str, package: &str) {
    match language {
        "python" => {
            if package.contains('-') {
                insert_dependency_package_token(out, &package.replace('-', "_"));
            }
            if let Some(alias) = python_distribution_import_alias(package) {
                insert_dependency_package_token(out, alias);
            }
        }
        "rust" => {
            if package.contains('-') {
                insert_dependency_package_token(out, &package.replace('-', "_"));
            }
        }
        _ => {}
    }
}

fn python_distribution_import_alias(package: &str) -> Option<&'static str> {
    match package.to_ascii_lowercase().as_str() {
        "argon2-cffi" => Some("argon2"),
        "beautifulsoup4" => Some("bs4"),
        "cx-oracle" => Some("cx_Oracle"),
        "djangorestframework" => Some("rest_framework"),
        "flask-limiter" => Some("flask_limiter"),
        "google-cloud-storage" => Some("google.cloud.storage"),
        "msgpack-python" => Some("msgpack"),
        "mysql-connector-python" => Some("mysql.connector"),
        "pillow" => Some("PIL"),
        "psycopg2-binary" => Some("psycopg2"),
        "pycryptodome" => Some("Crypto"),
        "python-jose" => Some("jose"),
        "python-ldap" => Some("ldap"),
        "python3-saml" => Some("onelogin.saml2"),
        "pyyaml" => Some("yaml"),
        _ => None,
    }
}

/// Collect every distinct signal key the rule advertises across the
/// `frameworks` / `packages` / `modules` / `imports` fields. The
/// dedup keeps the inventory's row keys stable when a rule mentions
/// the same package across multiple field families.
fn rule_signal_keys(rule: &Rule) -> Vec<String> {
    let mut keys = Vec::new();
    keys.extend(rule.frameworks.iter().cloned());
    keys.extend(rule.packages.iter().cloned());
    keys.extend(rule.modules.iter().cloned());
    keys.extend(rule.imports.iter().cloned());
    keys.sort();
    keys.dedup();
    keys
}

/// Gather signal labels and evidence file paths showing where one
/// dependency key is grounded — manifest filenames, lockfile filenames,
/// adapter-visible imports, or package names mentioned in dependency
/// manifests. Keeping this key-scoped prevents one matching package signal
/// from making every package/import listed on a broad multi-framework rule
/// look present in the workspace.
fn rule_key_evidence(
    rule: &Rule,
    key: &str,
    manifest_files: &[String],
    import_evidence_by_lang: &AHashMap<String, AHashMap<String, String>>,
    manifest_package_evidence_by_lang: &AHashMap<String, AHashMap<String, String>>,
) -> (Vec<String>, Vec<String>) {
    let mut signals = Vec::new();
    let mut evidence = Vec::new();
    // Manifest basename match: rule lists `pom.xml` / `Cargo.toml` / etc.
    for manifest_name in &rule.manifests {
        if let Some(path) = manifest_files.iter().find(|file_path| {
            Path::new(file_path.as_str())
                .file_name()
                .and_then(|name| name.to_str())
                == Some(manifest_name.as_str())
        }) {
            signals.push(format!("manifests:{manifest_name}"));
            evidence.push(path.clone());
        }
    }
    // Lockfile basename match: rule lists `Cargo.lock` / `pnpm-lock.yaml` / etc.
    for lockfile_name in &rule.lockfiles {
        if let Some(path) = manifest_files.iter().find(|file_path| {
            Path::new(file_path.as_str())
                .file_name()
                .and_then(|name| name.to_str())
                == Some(lockfile_name.as_str())
        }) {
            signals.push(format!("lockfiles:{lockfile_name}"));
            evidence.push(path.clone());
        }
    }
    if let Some(lang_import_evidence) = import_evidence_by_lang.get(&rule.language) {
        // Both `imports:` / `modules:` and `packages:` go through the
        // shared `import_matches_package` predicate (see `pkg.rs`).
        // The runtime matcher uses the same helper, so dependency
        // inventory and per-file package context gate cannot drift on what
        // counts as "this file imports package X" — including PHP
        // namespaces (`Cake\\Datasource`), Perl scope (`DBI::db`),
        // C/C++ header forms (`sqlite3.h`), and dotted prefixes.
        if rule.imports.iter().any(|needle| needle == key) {
            push_import_signal_for_key(&mut signals, &mut evidence, lang_import_evidence, "imports", key);
        }
        if rule.modules.iter().any(|needle| needle == key) {
            push_import_signal_for_key(&mut signals, &mut evidence, lang_import_evidence, "modules", key);
        }
        if rule.packages.iter().any(|needle| needle == key) {
            push_import_signal_for_key(&mut signals, &mut evidence, lang_import_evidence, "packages", key);
        }
        if rule.frameworks.iter().any(|needle| needle == key) {
            push_import_signal_for_key(
                &mut signals,
                &mut evidence,
                lang_import_evidence,
                "frameworks",
                key,
            );
        }
    }
    // Manifest-content scan: catches first-party packages that ARE the
    // workspace (e.g. a Java project whose own `pom.xml` declares
    // `<artifactId>log4j-core</artifactId>`) without an import line
    // anywhere in the source tree.
    if let Some(manifest_package_evidence) = manifest_package_evidence_by_lang.get(&rule.language) {
        if rule.packages.iter().any(|needle| needle == key) {
            if let Some(path) = manifest_package_evidence.get(key) {
                signals.push(format!("packages:{key}"));
                evidence.push(path.clone());
            }
        }
        if rule.frameworks.iter().any(|needle| needle == key) {
            if let Some(path) = manifest_package_evidence.get(key) {
                signals.push(format!("frameworks:{key}"));
                evidence.push(path.clone());
            }
        }
    }
    signals.sort();
    signals.dedup();
    evidence.sort();
    evidence.dedup();
    (signals, evidence)
}

fn push_import_signal_for_key(
    signals: &mut Vec<String>,
    evidence: &mut Vec<String>,
    lang_import_evidence: &AHashMap<String, String>,
    signal_prefix: &str,
    key: &str,
) {
    if let Some(file) = lang_import_evidence.get(key) {
        signals.push(format!("{signal_prefix}:{key}"));
        evidence.push(file.clone());
    }
}

/// True when `path` is a recognised package-manager manifest whose
/// content the inventory should scan for package-name evidence.
/// Anything not on this list (random YAML, dotenv, prose) is skipped
/// to avoid false positives from prose mentioning a package name.
fn is_dependency_manifest_file(path: &str) -> bool {
    let Some(basename) = Path::new(path).file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    is_dependency_manifest_basename(basename)
}

fn is_dependency_manifest_basename(basename: &str) -> bool {
    matches!(
        basename,
        "Cargo.toml"
            | "Cargo.lock"
            | "composer.json"
            | "composer.lock"
            | "Gemfile"
            | "Gemfile.lock"
            | "go.mod"
            | "go.sum"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "pom.xml"
            | "pyproject.toml"
            | "requirements.txt"
            | "settings.gradle"
            | "build.gradle"
            | "build.gradle.kts"
            | "yarn.lock"
    )
}

fn collect_manifest_package_evidence(
    pack: &Rulepack,
    manifest_files: &[String],
) -> AHashMap<String, AHashMap<String, String>> {
    let target_keys_by_lang = dependency_target_keys_by_language(pack);
    let mut evidence_by_language: AHashMap<String, AHashMap<String, String>> = AHashMap::new();
    for path in manifest_files {
        if !is_dependency_manifest_file(path) {
            continue;
        }
        let languages = dependency_manifest_languages(Path::new(path));
        if languages.is_empty() {
            continue;
        }
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(path, "manifest disappeared while scanning dependency inventory");
                continue;
            }
            Err(error) => {
                tracing::warn!(
                    path,
                    error_kind = ?error.kind(),
                    error = %error,
                    "failed to read manifest while scanning dependency inventory"
                );
                continue;
            }
        };
        let packages = dependency_manifest_package_tokens(&text);
        for language in languages {
            let Some(target_keys) = target_keys_by_lang.get(*language) else {
                continue;
            };
            let language_packages = dependency_manifest_packages_for_language(&packages, language);
            for package in language_packages {
                if target_keys.contains(package.as_str()) {
                    evidence_by_language
                        .entry((*language).to_string())
                        .or_default()
                        .entry(package)
                        .or_insert_with(|| path.clone());
                }
            }
        }
    }
    evidence_by_language
}

/// Walk `root` collecting relevant manifest and lockfile paths. The
/// traversal is intentionally not depth-limited: monorepos commonly place
/// package manifests many levels below the workspace root, and missing one
/// would make dependency evidence incomplete. The basename filter keeps the
/// inventory from retaining every regular file path in large repositories.
fn scan_manifest_files(root: &Path, pack: &Rulepack) -> Vec<String> {
    let target_names = manifest_target_names(pack);
    let mut paths = Vec::new();
    walk_dir(root, &target_names, &mut paths);
    paths.sort();
    paths.dedup();
    paths
}

fn manifest_target_names(pack: &Rulepack) -> AHashSet<String> {
    let mut target_names = AHashSet::new();
    for rule in pack.all_rules() {
        if !rule.enabled {
            continue;
        }
        target_names.extend(rule.manifests.iter().cloned());
        target_names.extend(rule.lockfiles.iter().cloned());
    }
    target_names
}

/// Recursive directory walker. Skips known vendored / build / cache
/// directory names so dependency inventory doesn't pick up evidence from
/// `node_modules/`, `target/`, `.venv/`, etc. — these would mistake
/// third-party manifests for first-party project evidence.
fn walk_dir(dir: &Path, target_names: &AHashSet<String>, out: &mut Vec<String>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(
                path = %dir.display(),
                "dependency inventory directory disappeared during scan"
            );
            return;
        }
        Err(error) => {
            tracing::warn!(
                path = %dir.display(),
                error_kind = ?error.kind(),
                error = %error,
                "failed to read dependency inventory directory"
            );
            return;
        }
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if dependency_metadata_dir_skipped(&name) {
            continue;
        }
        if path.is_dir() {
            walk_dir(&path, target_names, out);
        } else if path.is_file() && (target_names.contains(&name) || is_dependency_manifest_basename(&name)) {
            out.push(path.display().to_string());
        }
    }
}

/// Collect the first evidence file for every rule dependency key present in
/// workspace imports, keyed by language. The candidate generator mirrors
/// `import_matches_package` but runs once per import target instead of once
/// per `(rule key, import target)` pair.
fn collect_workspace_import_evidence(
    ws: &Workspace,
    pack: &Rulepack,
) -> AHashMap<String, AHashMap<String, String>> {
    let target_keys_by_lang = dependency_target_keys_by_language(pack);
    let db = ws.db();
    let mut evidence_by_language: AHashMap<String, AHashMap<String, String>> = AHashMap::new();
    for file in ws.vfs().all_files() {
        let Some(adapter) = db.adapter_for(file) else {
            continue;
        };
        let language = adapter.language_id().as_str().to_string();
        let Some(target_keys) = target_keys_by_lang.get(&language) else {
            continue;
        };
        let file_path = ws
            .vfs()
            .path(file)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Some(import_index) = db.import_index_uncached(file) {
            for import_spec in import_index.imports {
                for candidate in import_package_candidates(&import_spec.module) {
                    if target_keys.contains(candidate.as_str()) {
                        evidence_by_language
                            .entry(language.clone())
                            .or_default()
                            .entry(candidate)
                            .or_insert_with(|| file_path.clone());
                    }
                }
            }
        }
    }
    evidence_by_language
}

fn dependency_target_keys_by_language(pack: &Rulepack) -> AHashMap<String, AHashSet<String>> {
    let mut out: AHashMap<String, AHashSet<String>> = AHashMap::new();
    for rule in pack.all_rules() {
        if !rule.enabled {
            continue;
        }
        out.entry(rule.language.clone())
            .or_default()
            .extend(rule_signal_keys(rule));
    }
    out
}

fn import_package_candidates(imported: &str) -> Vec<String> {
    let imported = imported.strip_prefix("node:").unwrap_or(imported);
    let mut out = Vec::new();
    push_import_candidate(&mut out, imported);
    let header_stripped = imported
        .strip_suffix(".h")
        .or_else(|| imported.strip_suffix(".hpp"))
        .or_else(|| imported.strip_suffix(".hxx"))
        .unwrap_or(imported);
    push_import_candidate(&mut out, header_stripped);
    push_prefix_candidates(&mut out, imported, "/");
    push_prefix_candidates(&mut out, imported, ".");
    push_prefix_candidates(&mut out, imported, "\\");
    push_prefix_candidates(&mut out, imported, "::");
    push_prefix_candidates(&mut out, imported, "->");
    if header_stripped != imported {
        push_prefix_candidates(&mut out, header_stripped, "/");
        push_prefix_candidates(&mut out, header_stripped, ".");
        push_prefix_candidates(&mut out, header_stripped, "\\");
        push_prefix_candidates(&mut out, header_stripped, "::");
    }
    out
}

fn push_prefix_candidates(out: &mut Vec<String>, imported: &str, sep: &str) {
    let mut search_start = 0usize;
    while let Some(offset) = imported[search_start..].find(sep) {
        let absolute = search_start + offset;
        if absolute > 0 {
            push_import_candidate(out, &imported[..absolute]);
        }
        search_start = absolute + sep.len();
        if search_start >= imported.len() {
            break;
        }
    }
}

fn push_import_candidate(out: &mut Vec<String>, candidate: &str) {
    if candidate.is_empty() || out.iter().any(|existing| existing == candidate) {
        return;
    }
    out.push(candidate.to_string());
}

#[cfg(test)]
#[path = "deps_tests.rs"]
mod tests;
