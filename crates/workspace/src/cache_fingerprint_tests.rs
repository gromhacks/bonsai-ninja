use super::{
    dependency_metadata_fingerprint, dependency_metadata_fingerprint_for_sidecar,
    register_workspace_cache_root,
};
use std::path::PathBuf;

fn tempdir(name: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "bonsai-cache-fingerprint-{name}-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir(&path).expect("create temp dir");
    path
}

#[test]
fn dependency_metadata_fingerprint_changes_when_manifest_changes() {
    let root = tempdir("metadata-change");
    let manifest = root.join("requirements.txt");
    std::fs::write(&manifest, "flask==3.0.0\n").expect("write manifest");
    let before = dependency_metadata_fingerprint(&root);
    std::fs::write(&manifest, "flask==3.0.0\nrequests==2.32.0\n").expect("rewrite manifest");
    let after = dependency_metadata_fingerprint(&root);
    assert_ne!(before, after);
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn dependency_metadata_fingerprint_tracks_common_project_manifests() {
    let root = tempdir("metadata-common");
    let api = root.join("services").join("api");
    std::fs::create_dir_all(&api).expect("create nested project dir");
    std::fs::write(root.join("poetry.lock"), "package = []\n").expect("write poetry lock");
    std::fs::write(api.join("Service.csproj"), "<Project />\n").expect("write csproj");
    std::fs::write(api.join("requirements-dev.txt"), "pytest==8.0.0\n").expect("write requirements variant");

    let before = dependency_metadata_fingerprint(&root);
    std::fs::write(
        api.join("Service.csproj"),
        "<Project><PackageReference Include=\"Dapper\" /></Project>\n",
    )
    .expect("rewrite csproj");
    let after_csproj = dependency_metadata_fingerprint(&root);
    assert_ne!(before, after_csproj);

    std::fs::write(api.join("requirements-dev.txt"), "pytest==8.0.0\nruff==0.8.0\n")
        .expect("rewrite requirements variant");
    let after_requirements = dependency_metadata_fingerprint(&root);
    assert_ne!(after_csproj, after_requirements);
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn dependency_metadata_fingerprint_tracks_project_manifests_case_insensitively() {
    let root = tempdir("metadata-case");
    std::fs::write(root.join("SERVICE.CSPROJ"), "<Project />\n").expect("write uppercase csproj");
    std::fs::write(root.join("APP.SLN"), "Microsoft Visual Studio Solution File\n")
        .expect("write uppercase solution");

    let before = dependency_metadata_fingerprint(&root);
    std::fs::write(
        root.join("SERVICE.CSPROJ"),
        "<Project><PackageReference Include=\"Newtonsoft.Json\" /></Project>\n",
    )
    .expect("rewrite uppercase csproj");
    let after_csproj = dependency_metadata_fingerprint(&root);
    assert_ne!(
        before, after_csproj,
        "uppercase .CSPROJ files must be tracked as dependency metadata"
    );

    std::fs::write(
        root.join("APP.SLN"),
        "Microsoft Visual Studio Solution File\nProject(\"demo\") = \"demo\", \"demo.csproj\", \"{GUID}\"\n",
    )
    .expect("rewrite uppercase solution");
    let after_sln = dependency_metadata_fingerprint(&root);
    assert_ne!(
        after_csproj, after_sln,
        "uppercase .SLN files must be tracked as dependency metadata"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn dependency_metadata_fingerprint_tracks_deep_nested_manifest() {
    let root = tempdir("metadata-deep");
    let manifest_dir = root
        .join("a")
        .join("b")
        .join("c")
        .join("d")
        .join("e")
        .join("service");
    std::fs::create_dir_all(&manifest_dir).expect("create nested project dir");
    let manifest = manifest_dir.join("pom.xml");
    std::fs::write(&manifest, "<project />\n").expect("write deep manifest");

    let before = dependency_metadata_fingerprint(&root);
    std::fs::write(&manifest, "<project><dependencies /></project>\n").expect("rewrite deep manifest");
    let after = dependency_metadata_fingerprint(&root);

    assert_ne!(
        before, after,
        "deep dependency metadata must invalidate workspace sidecars"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn sidecar_fingerprint_resolves_workspace_root() {
    let root = tempdir("sidecar-root");
    let bonsai = root.join(".bonsai");
    std::fs::create_dir(&bonsai).expect("create bonsai dir");
    std::fs::write(root.join("package-lock.json"), "{}\n").expect("write lockfile");
    let sidecar = bonsai.join("dataflow.v3.factstore");
    assert_eq!(
        dependency_metadata_fingerprint_for_sidecar(&sidecar),
        dependency_metadata_fingerprint(&root)
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn external_sidecar_fingerprint_resolves_registered_workspace_root() {
    let root = tempdir("external-sidecar-root");
    std::fs::write(root.join("package-lock.json"), "{}\n").expect("write lockfile");
    let cache = register_workspace_cache_root(&root).expect("bind external cache");
    let sidecar = cache.join("dataflow.v3.factstore");
    assert_eq!(
        dependency_metadata_fingerprint_for_sidecar(&sidecar),
        dependency_metadata_fingerprint(&root)
    );
    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&cache).ok();
}

#[test]
fn unbound_external_sidecar_never_uses_legacy_zero_fingerprint() {
    let cache = tempdir("unbound-external-sidecar");
    let sidecar = cache.join("callgraph.v25.factstore");
    assert_eq!(
        dependency_metadata_fingerprint_for_sidecar(&sidecar),
        super::UNBOUND_WORKSPACE_DEPENDENCY_FINGERPRINT
    );
    assert_ne!(dependency_metadata_fingerprint_for_sidecar(&sidecar), 0);
    std::fs::remove_dir_all(cache).ok();
}
