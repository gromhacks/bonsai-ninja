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
use crate::pkg::import_matches_package;
use crate::rule::{Rule, Severity};
use ahash::{AHashMap, AHashSet};
use bonsai_common::dependency_metadata::dependency_metadata_dir_skipped;
use bonsai_lang_api::RefKind;
use bonsai_workspace::Workspace;
use serde::Serialize;
use std::path::Path;

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
    let imports_by_lang = collect_workspace_imports(ws);

    let mut by_key: AHashMap<(String, String), DependencyRow> = AHashMap::new();
    for rule in pack.all_rules() {
        if !rule.enabled {
            continue;
        }
        let keys = rule_signal_keys(rule);
        for key in keys {
            let (signals, evidence) = rule_evidence(rule, &manifest_files, &imports_by_lang);
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

/// Gather signal labels and evidence file paths showing where each
/// rule's package claim is grounded — manifest filenames, lockfile
/// filenames, adapter-visible imports, or package names mentioned in
/// dependency manifests. Returns `(signals, evidence)` deduped and
/// sorted for stable rendering.
fn rule_evidence(
    rule: &Rule,
    manifest_files: &[String],
    imports_by_lang: &AHashMap<String, Vec<(String, String)>>,
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
    if let Some(lang_imports) = imports_by_lang.get(&rule.language) {
        // Both `imports:` / `modules:` and `packages:` go through the
        // shared `import_matches_package` predicate (see `pkg.rs`).
        // The runtime matcher uses the same helper, so dependency
        // inventory and per-file package context gate cannot drift on what
        // counts as "this file imports package X" — including PHP
        // namespaces (`Cake\\Datasource`), Perl scope (`DBI::db`),
        // C/C++ header forms (`sqlite3.h`), and dotted prefixes.
        for needle in rule.imports.iter().chain(rule.modules.iter()) {
            for (file, imported) in lang_imports {
                if import_matches_package(imported, needle) {
                    signals.push(format!("imports:{needle}"));
                    evidence.push(file.clone());
                    break;
                }
            }
        }
        for needle in &rule.packages {
            for (file, imported) in lang_imports {
                if import_matches_package(imported, needle) {
                    signals.push(format!("packages:{needle}"));
                    evidence.push(file.clone());
                    break;
                }
            }
        }
    }
    // Manifest-content scan: catches first-party packages that ARE the
    // workspace (e.g. a Java project whose own `pom.xml` declares
    // `<artifactId>log4j-core</artifactId>`) without an import line
    // anywhere in the source tree.
    for needle in &rule.packages {
        for path in manifest_files {
            if !is_dependency_manifest_file(path) {
                continue;
            }
            if manifest_mentions_package(path, needle) {
                signals.push(format!("packages:{needle}"));
                evidence.push(path.clone());
                break;
            }
        }
    }
    signals.sort();
    signals.dedup();
    evidence.sort();
    evidence.dedup();
    (signals, evidence)
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

fn manifest_mentions_package(path: &str, package: &str) -> bool {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(path, "manifest disappeared while scanning dependency inventory");
            return false;
        }
        Err(error) => {
            tracing::warn!(
                path,
                error_kind = ?error.kind(),
                error = %error,
                "failed to read manifest while scanning dependency inventory"
            );
            return false;
        }
    };
    package_name_appears_bounded(&text, package)
}

/// Substring `text.contains(package)` was matching `log4j` inside
/// `log4j-core`, `express` inside `express-validator`, and similar
/// near-name false positives. This helper requires the package name
/// to sit at a non-identifier boundary (start of file, end of file,
/// or surrounded by chars that aren't part of an identifier or `-`
/// — `-` is part of npm / cargo names so it must be treated as
/// in-name).
fn package_name_appears_bounded(text: &str, package: &str) -> bool {
    if package.is_empty() {
        return false;
    }
    let text_bytes = text.as_bytes();
    let package_len = package.len();
    if text_bytes.len() < package_len {
        return false;
    }
    let mut start = 0usize;
    while start + package_len <= text_bytes.len() {
        let Some(found_offset) = text[start..].find(package) else {
            return false;
        };
        let absolute_pos = start + found_offset;
        // Boundary-check the chars on either side of the match.
        let before_ok = absolute_pos == 0 || !is_pkg_name_char(text_bytes[absolute_pos - 1]);
        let after_index = absolute_pos + package_len;
        let after_ok = after_index >= text_bytes.len() || !is_pkg_name_char(text_bytes[after_index]);
        if before_ok && after_ok {
            return true;
        }
        // Inner overlap — advance past this match attempt and retry.
        start = absolute_pos + 1;
    }
    false
}

/// True when the byte is part of a package-name identifier body.
/// Package-name body: alnum, plus the connectors common in npm /
/// cargo / maven / pypi names. Anything else (`<`, `>`, `"`, `:`,
/// `,`, whitespace, newline) is a boundary.
fn is_pkg_name_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b'@')
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

/// Collect every `(file_path, imported_target)` pair across the
/// workspace, keyed by language. Pulls from BOTH the per-decl
/// `RefKind::Import` refs and the dedicated `import_index` so rules
/// fire whichever shape the adapter emits for a given language.
fn collect_workspace_imports(ws: &Workspace) -> AHashMap<String, Vec<(String, String)>> {
    let db = ws.db();
    let global = db.global_index();
    let mut imports_by_language: AHashMap<String, Vec<(String, String)>> = AHashMap::new();
    for file in global.all_files() {
        let Some(adapter) = db.adapter_for(file) else {
            continue;
        };
        let language = adapter.language_id().as_str().to_string();
        let file_path = ws
            .vfs()
            .path(file)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Some(decl_index) = db.decl_index(file) {
            for reference in &decl_index.refs {
                if reference.kind == RefKind::Import {
                    imports_by_language
                        .entry(language.clone())
                        .or_default()
                        .push((file_path.clone(), reference.name.clone()));
                }
            }
        }
        if let Some(import_index) = db.import_index(file) {
            for import_spec in &import_index.imports {
                imports_by_language
                    .entry(language.clone())
                    .or_default()
                    .push((file_path.clone(), import_spec.module.clone()));
            }
        }
    }
    imports_by_language
}

#[cfg(test)]
#[path = "deps_tests.rs"]
mod tests;
