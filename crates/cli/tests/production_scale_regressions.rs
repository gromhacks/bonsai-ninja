//! Compact scale regressions that run in the ordinary workspace gate.
//!
//! The real-repository SLO lives in `elasticsearch_large_repo`; this file
//! keeps a deterministic adversarial case in every `cargo test --workspace`
//! run. Repeating the same short callable names across many modules catches
//! accidental global-name joins, quadratic candidate scans, and false
//! cross-module paths without relying on a network checkout.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    let mut path = std::env::current_dir().expect("cwd");
    path.push("../..");
    path.canonicalize().expect("repo root")
}

fn bin_path() -> PathBuf {
    option_env!("CARGO_BIN_EXE_bonsai-ninja")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join("target/debug/bonsai-ninja"))
}

fn temp_workspace(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "bonsai-module-collision-scale-{name}-{}",
        std::process::id()
    ))
}

fn write_module(root: &Path, shard: usize) {
    let package = root.join(format!("package_{shard:03}"));
    std::fs::create_dir_all(&package).expect("create scale package");
    std::fs::write(package.join("__init__.py"), "").expect("write package marker");
    std::fs::write(
        package.join("flow.py"),
        "def step(value):\n    return value\n\ndef entry(value):\n    return step(value)\n",
    )
    .expect("write collision module");
}

#[test]
fn repeated_short_names_keep_file_local_edges_at_scale() {
    const SHARDS: usize = 192;

    let workspace = temp_workspace("edges");
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace).expect("create scale workspace");
    for shard in 0..SHARDS {
        write_module(&workspace, shard);
    }

    let output = Command::new(bin_path())
        .args([
            "dump-edges",
            workspace.to_str().expect("workspace utf8"),
            "--from",
            "entry",
            "--to",
            "step",
            "--format",
            "json",
            "--all",
            "--no-cache",
            "--no-color",
            "--no-progress",
        ])
        .env("BONSAI_MEMORY_BUDGET_MB", "1024")
        .output()
        .expect("run scale dump-edges");
    assert!(
        output.status.success(),
        "scale dump-edges failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let edges: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("scale dump-edges JSON");
    assert_eq!(
        edges.len(),
        SHARDS,
        "each module must contribute exactly one local entry -> step edge"
    );
    for edge in &edges {
        assert_eq!(edge["caller_name"], "entry", "{edge}");
        assert_eq!(edge["callee_name"], "step", "{edge}");
        assert_eq!(
            edge["caller_file"], edge["callee_file"],
            "same-spelled functions in unrelated modules must never create a false cross-file edge: {edge}"
        );
        assert_eq!(
            edge["call_file"], edge["caller_file"],
            "call-site attribution drifted away from its compiler declaration: {edge}"
        );
    }

    let edge_id = edges[SHARDS / 2]["edge_id"]
        .as_str()
        .expect("stable scale edge id");
    let reopened = Command::new(bin_path())
        .args([
            "show",
            workspace.to_str().expect("workspace utf8"),
            "--id",
            edge_id,
            "--format",
            "json",
            "--all",
            "--no-cache",
            "--no-color",
            "--no-progress",
        ])
        .env("BONSAI_MEMORY_BUDGET_MB", "1024")
        .output()
        .expect("reopen scale edge id");
    assert!(
        reopened.status.success(),
        "scale show edge failed with {}\nstdout:\n{}\nstderr:\n{}",
        reopened.status,
        String::from_utf8_lossy(&reopened.stdout),
        String::from_utf8_lossy(&reopened.stderr)
    );
    let reopened: Vec<serde_json::Value> =
        serde_json::from_slice(&reopened.stdout).expect("scale show edge JSON");
    assert_eq!(reopened.len(), 1, "stable edge id must reopen one row");
    assert_eq!(reopened[0]["edge_id"], edge_id, "wrong edge reopened");

    let _ = std::fs::remove_dir_all(workspace);
}

#[test]
fn cache_rebuild_stats_and_clear_complete_on_a_many_file_workspace() {
    const SHARDS: usize = 192;

    let workspace = temp_workspace("cache");
    let cache = temp_workspace("cache-sidecars");
    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&cache);
    std::fs::create_dir_all(&workspace).expect("create cache scale workspace");
    for shard in 0..SHARDS {
        write_module(&workspace, shard);
    }

    let run_cache = |args: &[&str]| {
        Command::new(bin_path())
            .args(args)
            .args(["--no-color", "--no-progress"])
            .env("BONSAI_WORKSPACE_DIR", &cache)
            .env("BONSAI_MEMORY_BUDGET_MB", "1024")
            .output()
            .expect("run scale cache command")
    };
    let workspace_arg = workspace.to_str().expect("workspace utf8");
    let rebuilt = run_cache(&["cache", "rebuild", workspace_arg]);
    assert!(
        rebuilt.status.success(),
        "scale cache rebuild failed with {}\nstdout:\n{}\nstderr:\n{}",
        rebuilt.status,
        String::from_utf8_lossy(&rebuilt.stdout),
        String::from_utf8_lossy(&rebuilt.stderr)
    );

    let stats = run_cache(&["cache", "stats", workspace_arg, "--format", "json"]);
    assert!(stats.status.success(), "scale cache stats failed: {stats:?}");
    let stats: serde_json::Value = serde_json::from_slice(&stats.stdout).expect("scale cache stats JSON");
    assert_eq!(stats["validation"]["semantic_ready"], true, "{stats}");
    assert_eq!(stats["validation"]["structural_ready"], true, "{stats}");
    assert!(
        stats["compiler_object_sidecar_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0),
        "rebuild did not publish compiler objects: {stats}"
    );
    assert!(
        stats["idg_sidecar_bytes"].as_u64().is_some_and(|bytes| bytes > 0),
        "rebuild did not publish the exact IDG: {stats}"
    );

    let cleared = run_cache(&["cache", "clear", workspace_arg]);
    assert!(
        cleared.status.success(),
        "scale cache clear failed with {}\nstdout:\n{}\nstderr:\n{}",
        cleared.status,
        String::from_utf8_lossy(&cleared.stdout),
        String::from_utf8_lossy(&cleared.stderr)
    );
    assert!(
        !cache.exists(),
        "cache clear retained the canonical sidecar directory: {}",
        cache.display()
    );

    let _ = std::fs::remove_dir_all(workspace);
    let _ = std::fs::remove_dir_all(cache);
}

#[test]
fn deeply_nested_java_semantic_generation_is_stack_safe() {
    const DEPTH: usize = 2_048;

    let workspace = temp_workspace("deep-java");
    let cache = temp_workspace("deep-java-sidecars");
    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&cache);
    std::fs::create_dir_all(&workspace).expect("create deep Java workspace");

    let mut source = String::from(
        "package scale;\npublic final class Deep {\n  public static String evaluate(String value) {\n",
    );
    for _ in 0..DEPTH {
        source.push_str("    if (value != null) {\n");
    }
    source.push_str("      return value.trim();\n");
    for _ in 0..DEPTH {
        source.push_str("    }\n");
    }
    source.push_str("    return \"\";\n  }\n}\n");
    std::fs::write(workspace.join("Deep.java"), source).expect("write deep Java source");

    let rebuilt = Command::new(bin_path())
        .args([
            "cache",
            "rebuild",
            workspace.to_str().expect("workspace utf8"),
            "--no-color",
            "--no-progress",
        ])
        .env("BONSAI_WORKSPACE_DIR", &cache)
        .env("BONSAI_MEMORY_BUDGET_MB", "1024")
        .output()
        .expect("run deep Java semantic generation");
    assert!(
        rebuilt.status.success(),
        "deep Java semantic generation failed with {}\nstdout:\n{}\nstderr:\n{}",
        rebuilt.status,
        String::from_utf8_lossy(&rebuilt.stdout),
        String::from_utf8_lossy(&rebuilt.stderr)
    );

    let stats = Command::new(bin_path())
        .args([
            "cache",
            "stats",
            workspace.to_str().expect("workspace utf8"),
            "--format",
            "json",
            "--no-color",
            "--no-progress",
        ])
        .env("BONSAI_WORKSPACE_DIR", &cache)
        .output()
        .expect("read deep Java cache stats");
    assert!(stats.status.success(), "deep Java cache stats failed: {stats:?}");
    let stats: serde_json::Value = serde_json::from_slice(&stats.stdout).expect("deep Java cache stats JSON");
    assert_eq!(stats["validation"]["semantic_ready"], true, "{stats}");
    assert_eq!(stats["validation"]["structural_ready"], true, "{stats}");

    let _ = std::fs::remove_dir_all(workspace);
    let _ = std::fs::remove_dir_all(cache);
}
