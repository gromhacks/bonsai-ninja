use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct WorkspaceSemanticContextSummary {
    pub indexed_files: usize,
    pub first_party_files: usize,
    pub dependency_files: usize,
    pub generated_files: usize,
    pub excluded_files: usize,
    pub module_roots: usize,
    pub dependency_roots: usize,
    pub generated_roots: usize,
    pub excluded_roots: usize,
    pub toolchain_manifests: usize,
    pub configured_source_variants: usize,
    pub source_transformations: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkspaceSemanticContext {
    pub workspace_root: Option<String>,
    pub summary: WorkspaceSemanticContextSummary,
    pub module_roots: Vec<WorkspaceContextRoot>,
    pub dependency_roots: Vec<WorkspaceContextRoot>,
    pub generated_roots: Vec<WorkspaceContextRoot>,
    pub excluded_roots: Vec<WorkspaceContextRoot>,
    pub toolchain_manifests: Vec<WorkspaceToolchainManifest>,
    pub configured_source_variants: Vec<WorkspaceSourceVariant>,
    pub source_transformations: Vec<WorkspaceSourceTransformation>,
    pub incomplete_reasons: Vec<String>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceContextRootKind {
    Module,
    Dependency,
    Generated,
    Excluded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkspaceContextRoot {
    pub path: String,
    pub kind: WorkspaceContextRootKind,
    pub reason: String,
    pub indexed_files: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkspaceToolchainManifest {
    pub path: String,
    pub kind: String,
    pub scope: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkspaceSourceVariant {
    pub path: String,
    pub kind: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkspaceSourceTransformation {
    pub path: String,
    pub kind: String,
    pub evidence: String,
}

#[derive(Default)]
struct ContextRootAccumulator {
    reasons: BTreeSet<String>,
    indexed_files: usize,
}

pub(crate) fn build_workspace_semantic_context(
    root: Option<&Path>,
    files: &[PathBuf],
    discover_roots: bool,
) -> WorkspaceSemanticContext {
    let mut module_roots: BTreeMap<String, ContextRootAccumulator> = BTreeMap::new();
    let mut dependency_roots: BTreeMap<String, ContextRootAccumulator> = BTreeMap::new();
    let mut generated_roots: BTreeMap<String, ContextRootAccumulator> = BTreeMap::new();
    let mut excluded_roots: BTreeMap<String, ContextRootAccumulator> = BTreeMap::new();
    let mut first_party_files = 0usize;
    let mut dependency_files = 0usize;
    let mut generated_files = 0usize;
    let mut excluded_files = 0usize;
    let mut relative_files = Vec::with_capacity(files.len());

    for file in files {
        let relative = context_relative_path(root, file);
        relative_files.push(context_path_string(&relative));
        match classify_context_path(&relative) {
            Some((WorkspaceContextRootKind::Dependency, reason, root_path)) => {
                dependency_files += 1;
                add_context_root(&mut dependency_roots, context_path_string(&root_path), reason, 1);
            }
            Some((WorkspaceContextRootKind::Generated, reason, root_path)) => {
                generated_files += 1;
                add_context_root(&mut generated_roots, context_path_string(&root_path), reason, 1);
            }
            Some((WorkspaceContextRootKind::Excluded, reason, root_path)) => {
                excluded_files += 1;
                add_context_root(&mut excluded_roots, context_path_string(&root_path), reason, 1);
            }
            Some((WorkspaceContextRootKind::Module, reason, root_path)) => {
                first_party_files += 1;
                add_context_root(&mut module_roots, context_path_string(&root_path), reason, 1);
            }
            None => {
                first_party_files += 1;
                add_context_root(
                    &mut module_roots,
                    context_path_string(&source_module_root(&relative)),
                    "indexed_source_tree",
                    1,
                );
            }
        }
    }

    let mut incomplete_reasons = Vec::new();
    if discover_roots {
        if let Some(root) = root {
            discover_context_roots_from_disk(
                root,
                &mut dependency_roots,
                &mut generated_roots,
                &mut excluded_roots,
                &mut incomplete_reasons,
            );
        } else {
            incomplete_reasons.push(
                "workspace root unavailable; skipped filesystem discovery of excluded roots".to_string(),
            );
        }
    }

    let toolchain_manifests = collect_toolchain_manifests(root, files);
    for manifest in &toolchain_manifests {
        annotate_module_roots_for_manifest(
            &mut module_roots,
            &manifest.scope,
            format!("toolchain_manifest:{}", manifest.kind),
            count_files_under_context_path(&relative_files, &manifest.scope),
        );
    }
    if files.is_empty() && module_roots.is_empty() {
        add_context_root(&mut module_roots, ".".to_string(), "workspace_root", 0);
    }

    let module_roots = finish_context_roots(module_roots, WorkspaceContextRootKind::Module);
    let dependency_roots = finish_context_roots(dependency_roots, WorkspaceContextRootKind::Dependency);
    let generated_roots = finish_context_roots(generated_roots, WorkspaceContextRootKind::Generated);
    let excluded_roots = finish_context_roots(excluded_roots, WorkspaceContextRootKind::Excluded);
    let configured_source_variants = configured_source_variants_from_manifests(&toolchain_manifests);
    let source_transformations = source_transformations_from_roots(&generated_roots, &excluded_roots);
    let summary = WorkspaceSemanticContextSummary {
        indexed_files: files.len(),
        first_party_files,
        dependency_files,
        generated_files,
        excluded_files,
        module_roots: module_roots.len(),
        dependency_roots: dependency_roots.len(),
        generated_roots: generated_roots.len(),
        excluded_roots: excluded_roots.len(),
        toolchain_manifests: toolchain_manifests.len(),
        configured_source_variants: configured_source_variants.len(),
        source_transformations: source_transformations.len(),
    };

    WorkspaceSemanticContext {
        workspace_root: root.map(|path| path.display().to_string()),
        summary,
        module_roots,
        dependency_roots,
        generated_roots,
        excluded_roots,
        toolchain_manifests,
        configured_source_variants,
        source_transformations,
        incomplete_reasons,
    }
}

fn add_context_root(
    roots: &mut BTreeMap<String, ContextRootAccumulator>,
    path: String,
    reason: impl Into<String>,
    indexed_files: usize,
) {
    let entry = roots
        .entry(if path.is_empty() { ".".to_string() } else { path })
        .or_default();
    entry.reasons.insert(reason.into());
    entry.indexed_files = entry.indexed_files.saturating_add(indexed_files);
}

/// Attach another reason to an already-counted source root without counting
/// its files a second time. Toolchain manifests describe the same source
/// files classified above; they are evidence for the root, not another copy
/// of the root.
fn annotate_module_roots_for_manifest(
    roots: &mut BTreeMap<String, ContextRootAccumulator>,
    scope: &str,
    reason: impl Into<String>,
    indexed_files: usize,
) {
    let reason = reason.into();
    let scope = if scope.is_empty() { "." } else { scope };
    let mut matched = false;
    for (path, entry) in roots.iter_mut() {
        let same_or_nested = scope == "."
            || path == scope
            || path.starts_with(&format!("{scope}/"))
            || scope.starts_with(&format!("{path}/"));
        if same_or_nested {
            entry.reasons.insert(reason.clone());
            matched = true;
        }
    }
    if !matched {
        let entry = roots.entry(scope.to_string()).or_default();
        entry.reasons.insert(reason);
        entry.indexed_files = indexed_files;
    }
}

fn finish_context_roots(
    roots: BTreeMap<String, ContextRootAccumulator>,
    kind: WorkspaceContextRootKind,
) -> Vec<WorkspaceContextRoot> {
    roots
        .into_iter()
        .map(|(path, acc)| WorkspaceContextRoot {
            path,
            kind,
            reason: acc.reasons.into_iter().collect::<Vec<_>>().join(","),
            indexed_files: acc.indexed_files,
        })
        .collect()
}

pub(crate) fn context_relative_path(root: Option<&Path>, path: &Path) -> PathBuf {
    root.and_then(|root| path.strip_prefix(root).ok())
        .unwrap_or(path)
        .to_path_buf()
}

fn context_path_string(path: &Path) -> String {
    let mut rendered = path.to_string_lossy().replace('\\', "/");
    if std::path::MAIN_SEPARATOR != '/' {
        rendered = rendered.replace(std::path::MAIN_SEPARATOR, "/");
    }
    if rendered.is_empty() {
        ".".to_string()
    } else {
        rendered
    }
}

fn classify_context_path(relative: &Path) -> Option<(WorkspaceContextRootKind, &'static str, PathBuf)> {
    let mut prefix = PathBuf::new();
    let mut source_layout_depth = None;
    for component in relative.components() {
        let std::path::Component::Normal(segment) = component else {
            continue;
        };
        prefix.push(segment);
        let Some(segment) = segment.to_str() else {
            continue;
        };
        // Once a path has crossed `src/<source-set>/<language-or-resource>`,
        // later directory names are compiler/package namespace, not workspace
        // roles. Real code such as `org.elasticsearch.env`, a package named
        // `gradle`, or a package named `deps` must remain first party.
        // Dot metadata and package-manager cache directories stay structural
        // even when nested inside a source tree.
        if source_layout_depth.is_some_and(|depth| depth >= 2) {
            if let Some((kind, reason)) = classify_intrinsic_source_metadata_segment(segment) {
                return Some((kind, reason, prefix));
            }
            continue;
        }
        if let Some((kind, reason)) = classify_context_segment(segment) {
            return Some((kind, reason, prefix));
        }
        if segment.eq_ignore_ascii_case("src") {
            source_layout_depth = Some(0);
        } else if let Some(depth) = source_layout_depth.as_mut() {
            *depth += 1;
        }
    }
    let name = relative.file_name().and_then(|s| s.to_str())?;
    let lower = name.to_ascii_lowercase();
    if lower.contains(".min.") || lower.contains("-min.") {
        return Some((
            WorkspaceContextRootKind::Generated,
            "minified_filename",
            relative
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        ));
    }
    None
}

fn classify_intrinsic_source_metadata_segment(
    segment: &str,
) -> Option<(WorkspaceContextRootKind, &'static str)> {
    match segment.to_ascii_lowercase().as_str() {
        "node_modules" | "bower_components" | "site-packages" => {
            Some((WorkspaceContextRootKind::Dependency, "dependency_root"))
        }
        ".bonsai" | ".git" | ".hg" | ".svn" | ".gradle" | ".tox" | ".mypy_cache" | ".pytest_cache"
        | "__pycache__" | ".venv" => Some((WorkspaceContextRootKind::Excluded, "excluded_tooling_root")),
        _ => None,
    }
}

fn classify_context_segment(segment: &str) -> Option<(WorkspaceContextRootKind, &'static str)> {
    match segment.to_ascii_lowercase().as_str() {
        "node_modules" | "bower_components" | "vendor" | "deps" | "third_party" | "external"
        | "subprojects" | "pods" | "carthage" | "site-packages" => {
            Some((WorkspaceContextRootKind::Dependency, "dependency_root"))
        }
        "generated" | "gen" | "autogen" | "deriveddata" => {
            Some((WorkspaceContextRootKind::Generated, "generated_source_root"))
        }
        "dist" | "build" | "target" | "out" | ".next" | ".nuxt" | "bin" | "obj" => {
            Some((WorkspaceContextRootKind::Generated, "build_output_root"))
        }
        ".bonsai" | ".git" | ".hg" | ".svn" | ".gradle" | "gradle" | ".tox" | ".mypy_cache"
        | ".pytest_cache" | "__pycache__" | "coverage" | ".coverage" | ".venv" | "venv" | ".env" | "env" => {
            Some((WorkspaceContextRootKind::Excluded, "excluded_tooling_root"))
        }
        _ => None,
    }
}

fn source_module_root(relative: &Path) -> PathBuf {
    let mut normal_segments = relative.components().filter_map(|component| match component {
        std::path::Component::Normal(segment) => Some(segment.to_os_string()),
        _ => None,
    });
    let Some(first) = normal_segments.next() else {
        return PathBuf::from(".");
    };
    if normal_segments.next().is_none() {
        PathBuf::from(".")
    } else {
        PathBuf::from(first)
    }
}

fn discover_context_roots_from_disk(
    root: &Path,
    dependency_roots: &mut BTreeMap<String, ContextRootAccumulator>,
    generated_roots: &mut BTreeMap<String, ContextRootAccumulator>,
    excluded_roots: &mut BTreeMap<String, ContextRootAccumulator>,
    incomplete_reasons: &mut Vec<String>,
) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let read_dir = match fs::read_dir(&dir) {
            Ok(read_dir) => read_dir,
            Err(error) => {
                incomplete_reasons.push(format!(
                    "could not inspect context directory {}: {error}",
                    context_path_string(&context_relative_path(Some(root), &dir))
                ));
                continue;
            }
        };
        let mut children = read_dir
            .filter_map(Result::ok)
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .filter(|file_type| file_type.is_dir())
                    .map(|_| entry.path())
            })
            .collect::<Vec<_>>();
        children.sort();
        for child in children.into_iter().rev() {
            let relative = context_relative_path(Some(root), &child);
            let Some((kind, reason, root_path)) = classify_context_path(&relative) else {
                stack.push(child);
                continue;
            };
            let rendered = context_path_string(&root_path);
            match kind {
                WorkspaceContextRootKind::Dependency => {
                    add_context_root(dependency_roots, rendered, reason, 0);
                }
                WorkspaceContextRootKind::Generated => {
                    add_context_root(generated_roots, rendered, reason, 0);
                }
                WorkspaceContextRootKind::Excluded => {
                    add_context_root(excluded_roots, rendered, reason, 0);
                }
                WorkspaceContextRootKind::Module => {}
            }
        }
    }
}

fn collect_toolchain_manifests(root: Option<&Path>, files: &[PathBuf]) -> Vec<WorkspaceToolchainManifest> {
    let mut dirs = BTreeSet::new();
    if let Some(root) = root {
        dirs.insert(root.to_path_buf());
    }
    for file in files {
        let Some(mut dir) = file.parent() else {
            continue;
        };
        loop {
            if root.is_none_or(|root| dir.starts_with(root)) {
                dirs.insert(dir.to_path_buf());
            }
            if root.is_some_and(|root| dir == root) {
                break;
            }
            let Some(parent) = dir.parent() else {
                break;
            };
            dir = parent;
        }
    }

    let mut manifests = BTreeMap::new();
    for dir in dirs {
        for (name, kind) in KNOWN_TOOLCHAIN_MANIFESTS {
            let path = dir.join(name);
            if path.is_file() {
                insert_toolchain_manifest(&mut manifests, root, &path, kind);
            }
        }
        let Ok(read_dir) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in read_dir.filter_map(Result::ok) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
                continue;
            };
            if ext.eq_ignore_ascii_case("csproj") || ext.eq_ignore_ascii_case("sln") {
                insert_toolchain_manifest(&mut manifests, root, &path, "project_manifest");
            }
        }
    }
    manifests.into_values().collect()
}

const KNOWN_TOOLCHAIN_MANIFESTS: &[(&str, &str)] = &[
    ("compile_commands.json", "compile_database"),
    ("Cargo.toml", "package_manifest"),
    ("package.json", "package_manifest"),
    ("pnpm-lock.yaml", "lockfile"),
    ("yarn.lock", "lockfile"),
    ("package-lock.json", "lockfile"),
    ("go.mod", "package_manifest"),
    ("go.sum", "lockfile"),
    ("pyproject.toml", "package_manifest"),
    ("requirements.txt", "dependency_manifest"),
    ("Pipfile", "dependency_manifest"),
    ("poetry.lock", "lockfile"),
    ("pom.xml", "build_manifest"),
    ("build.gradle", "build_manifest"),
    ("settings.gradle", "build_manifest"),
    ("composer.json", "package_manifest"),
    ("Gemfile", "dependency_manifest"),
    ("mix.exs", "package_manifest"),
    ("rebar.config", "package_manifest"),
    ("pubspec.yaml", "package_manifest"),
    ("Package.swift", "package_manifest"),
    ("CMakeLists.txt", "build_manifest"),
    ("Makefile", "build_manifest"),
    ("foundry.toml", "build_manifest"),
    ("hardhat.config.js", "build_manifest"),
    ("hardhat.config.ts", "build_manifest"),
];

fn insert_toolchain_manifest(
    manifests: &mut BTreeMap<String, WorkspaceToolchainManifest>,
    root: Option<&Path>,
    path: &Path,
    kind: &str,
) {
    let manifest_path = context_path_string(&context_relative_path(root, path));
    let scope = path
        .parent()
        .map(|parent| context_path_string(&context_relative_path(root, parent)))
        .unwrap_or_else(|| ".".to_string());
    manifests
        .entry(manifest_path.clone())
        .or_insert_with(|| WorkspaceToolchainManifest {
            path: manifest_path,
            kind: kind.to_string(),
            scope,
        });
}

fn count_files_under_context_path(relative_files: &[String], scope: &str) -> usize {
    if scope == "." {
        return relative_files.len();
    }
    let prefix = format!("{scope}/");
    relative_files
        .iter()
        .filter(|path| path.as_str() == scope || path.starts_with(&prefix))
        .count()
}

fn configured_source_variants_from_manifests(
    manifests: &[WorkspaceToolchainManifest],
) -> Vec<WorkspaceSourceVariant> {
    manifests
        .iter()
        .filter_map(|manifest| {
            let kind = match manifest.kind.as_str() {
                "compile_database" => "configured_translation_units",
                "build_manifest" => "build_configured_source",
                _ => return None,
            };
            Some(WorkspaceSourceVariant {
                path: manifest.scope.clone(),
                kind: kind.to_string(),
                evidence: manifest.path.clone(),
            })
        })
        .collect()
}

fn source_transformations_from_roots(
    generated_roots: &[WorkspaceContextRoot],
    excluded_roots: &[WorkspaceContextRoot],
) -> Vec<WorkspaceSourceTransformation> {
    let generated = generated_roots.iter().map(|root| WorkspaceSourceTransformation {
        path: root.path.clone(),
        kind: "generated_or_built_source".to_string(),
        evidence: root.reason.clone(),
    });
    let excluded = excluded_roots.iter().map(|root| WorkspaceSourceTransformation {
        path: root.path.clone(),
        kind: "excluded_source_tree".to_string(),
        evidence: root.reason.clone(),
    });
    generated.chain(excluded).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_discovery_has_no_directory_or_depth_ceiling() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        for index in 0..4_100 {
            fs::create_dir(temp.path().join(format!("unit_{index:04}"))).expect("source directory");
        }
        let dependency = temp
            .path()
            .join("unit_4099")
            .join("a")
            .join("b")
            .join("c")
            .join("d")
            .join("e")
            .join("node_modules");
        fs::create_dir_all(&dependency).expect("deep dependency directory");

        let context = build_workspace_semantic_context(Some(temp.path()), &[], true);

        assert!(
            context
                .dependency_roots
                .iter()
                .any(|root| root.path == "unit_4099/a/b/c/d/e/node_modules"),
            "deep dependency roots after more than 4096 source directories must be discovered: {context:?}"
        );
        assert!(context.incomplete_reasons.is_empty(), "{context:?}");
    }

    #[test]
    fn toolchain_manifest_annotation_does_not_double_count_source_files() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        fs::write(temp.path().join("pom.xml"), "<project/>").expect("manifest");
        let first = temp.path().join("src/A.java");
        let second = temp.path().join("src/B.java");
        fs::create_dir_all(first.parent().expect("source parent")).expect("source directory");
        fs::write(&first, "class A {}").expect("first source");
        fs::write(&second, "class B {}").expect("second source");

        let context =
            build_workspace_semantic_context(Some(temp.path()), &[first.clone(), second.clone()], false);

        assert_eq!(context.summary.indexed_files, 2);
        assert_eq!(
            context
                .module_roots
                .iter()
                .map(|root| root.indexed_files)
                .sum::<usize>(),
            2,
            "manifest evidence must not turn two indexed files into four"
        );
    }

    #[test]
    fn compiler_package_names_are_not_misclassified_as_workspace_roots() {
        assert_eq!(
            classify_context_path(Path::new(
                "server/src/main/java/org/elasticsearch/env/Environment.java"
            )),
            None
        );
        assert_eq!(
            classify_context_path(Path::new(
                "build-conventions/src/main/java/org/elasticsearch/gradle/Plugin.java"
            )),
            None
        );
        assert_eq!(
            classify_context_path(Path::new(
                "server/src/test/java/org/elasticsearch/deps/DependencyTests.java"
            )),
            None
        );
        assert_eq!(
            classify_context_path(Path::new("server/src/main/generated/Generated.java")),
            Some((
                WorkspaceContextRootKind::Generated,
                "generated_source_root",
                PathBuf::from("server/src/main/generated")
            ))
        );
        assert_eq!(
            classify_context_path(Path::new(
                "server/src/main/java/org/elasticsearch/.bonsai/state.java"
            )),
            Some((
                WorkspaceContextRootKind::Excluded,
                "excluded_tooling_root",
                PathBuf::from("server/src/main/java/org/elasticsearch/.bonsai")
            ))
        );
    }
}
