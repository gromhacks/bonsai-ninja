use super::{
    collect_dependency_metadata_fingerprints, dependency_metadata_dir_skipped, is_dependency_metadata_file,
    walk_dependency_metadata_files,
};
use std::path::PathBuf;

fn tempdir(name: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "bonsai-common-dependency-metadata-{name}-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir(&path).expect("create temp dir");
    path
}

#[test]
fn dependency_metadata_classifies_common_semantic_inputs() {
    for name in [
        "go.work",
        "go.work.sum",
        "requirements-dev.txt",
        "Service.csproj",
        "Directory.Build.props",
        "Cargo.lock",
        "pom.xml",
        "package-lock.json",
    ] {
        assert!(is_dependency_metadata_file(name), "{name}");
    }

    for name in [
        "node_modules",
        "vendor",
        "target",
        ".git",
        ".bonsai",
        "__pycache__",
        ".venv",
    ] {
        assert!(dependency_metadata_dir_skipped(name), "{name}");
    }
}

#[test]
fn dependency_metadata_walk_is_not_depth_limited() {
    let root = tempdir("deep");
    let mut dir = root.clone();
    for segment in ["one", "two", "three", "four", "five", "six"] {
        dir = dir.join(segment);
    }
    std::fs::create_dir_all(&dir).expect("create deep dirs");
    let manifest = dir.join("pom.xml");
    std::fs::write(&manifest, "<project />\n").expect("write manifest");

    let files = collect_dependency_metadata_fingerprints(&root).expect("collect metadata");
    assert!(
        files
            .iter()
            .any(|file| file.relative_path.ends_with("six/pom.xml")),
        "dependency metadata below four directories must still invalidate caches: {files:?}"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn dependency_metadata_walk_skips_dependency_output_dirs() {
    let root = tempdir("skip");
    let vendored = root.join("node_modules").join("pkg");
    std::fs::create_dir_all(&vendored).expect("create skipped dir");
    std::fs::write(vendored.join("package-lock.json"), "{}\n").expect("write skipped lock");
    std::fs::write(root.join("package-lock.json"), "{}\n").expect("write root lock");

    let mut paths = Vec::new();
    walk_dependency_metadata_files(&root, |_path, rel| {
        paths.push(rel.to_string());
        Ok(())
    })
    .expect("walk metadata");

    assert_eq!(paths, vec!["package-lock.json"]);
    std::fs::remove_dir_all(root).ok();
}
