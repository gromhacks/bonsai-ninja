//! Contract tests for the `help` command module (help, `--help`, and parse
//! errors share one themed rendering), the `tree` / `read-file` module
//! connections, and the workspace context carried by `index`.

use std::path::PathBuf;
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn ws_path() -> PathBuf {
    repo_root().join("test-fixtures/languages/python/micro")
}

fn bin_path() -> Option<PathBuf> {
    if let Some(path) = option_env!("CARGO_BIN_EXE_bonsai-ninja") {
        return Some(PathBuf::from(path));
    }
    let p = repo_root().join("target/release/bonsai-ninja");
    if !p.exists() {
        eprintln!(
            "skipping help/connections test: binary not built ({})",
            p.display()
        );
        return None;
    }
    Some(p)
}

fn run_raw(args: &[&str]) -> Option<Output> {
    let bin = bin_path()?;
    Some(
        Command::new(bin)
            .args(args)
            .arg("--no-color")
            .arg("--no-progress")
            .env("COLUMNS", "200")
            .env_remove("BONSAI_CONTEXT")
            .output()
            .expect("run bonsai-ninja"),
    )
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

const GROUPS: &[&str] = &[
    "Workspace",
    "Cache",
    "Navigation",
    "Browse",
    "Flow",
    "Security",
    "Debug",
];

#[test]
fn help_command_prints_the_grouped_menu() {
    let Some(out) = run_raw(&["help"]) else {
        return;
    };
    assert!(out.status.success(), "help must exit 0: {}", stderr_of(&out));
    let text = stdout_of(&out);
    assert!(text.contains("COMMAND GROUPS"), "menu heading missing:\n{text}");
    let mut last = 0;
    for group in GROUPS {
        let idx = text
            .find(&format!("  {group}\n"))
            .unwrap_or_else(|| panic!("group `{group}` missing from menu:\n{text}"));
        assert!(idx > last, "group `{group}` is out of workflow order:\n{text}");
        last = idx;
    }
    for retired in ["trace", "path", "slice", "symbol-summary", "context"] {
        assert!(
            !text.contains(&format!("    {retired} ")),
            "retired command `{retired}` still listed:\n{text}"
        );
    }
    let with_flag = stdout_of(&run_raw(&["--help"]).expect("binary"));
    assert_eq!(text, with_flag, "`help` and `--help` must render the same menu");
}

#[test]
fn help_command_opens_one_command_reference() {
    let Some(out) = run_raw(&["help", "inspect-graph"]) else {
        return;
    };
    assert!(out.status.success());
    let text = stdout_of(&out);
    assert!(
        text.contains("USAGE: bonsai-ninja inspect-graph"),
        "help <command> must render that command's reference:\n{text}"
    );
    let nested = stdout_of(&run_raw(&["help", "security", "taint-analysis"]).expect("binary"));
    assert!(
        nested.contains("taint-analysis"),
        "nested command path must resolve:\n{nested}"
    );
    let flag_form = stdout_of(&run_raw(&["inspect-graph", "--help"]).expect("binary"));
    assert_eq!(
        text, flag_form,
        "`help inspect-graph` and `inspect-graph --help` must match"
    );
}

#[test]
fn unknown_command_renders_the_themed_error_and_menu() {
    let Some(out) = run_raw(&["help", "definitely-not-a-command"]) else {
        return;
    };
    assert_eq!(out.status.code(), Some(2), "unknown help target must exit 2");
    let text = stdout_of(&out);
    assert!(
        text.contains("error: unknown command `definitely-not-a-command`") && text.contains("COMMAND GROUPS"),
        "help <unknown> must print the themed error and the menu:\n{text}"
    );

    let bad = run_raw(&["definitely-not-a-command", "./src"]).expect("binary");
    assert_eq!(bad.status.code(), Some(2), "unknown command must exit 2");
    let err = stderr_of(&bad);
    assert!(
        err.starts_with("error: ")
            && err.contains("COMMAND GROUPS")
            && err.contains("bonsai-ninja help <command>"),
        "an unknown command must render the same themed menu on stderr:\n{err}"
    );
}

#[test]
fn bad_arguments_render_the_command_help_in_the_same_format() {
    let Some(out) = run_raw(&["inspect-graph"]) else {
        return;
    };
    assert_eq!(out.status.code(), Some(2));
    let err = stderr_of(&out);
    assert!(
        err.starts_with("error: ") && err.contains("USAGE: bonsai-ninja inspect-graph"),
        "missing workspace must show inspect-graph's own help:\n{err}"
    );
    assert!(
        err.contains("bonsai-ninja help inspect-graph"),
        "error output must point at the help command:\n{err}"
    );
    let reference = stdout_of(&run_raw(&["help", "inspect-graph"]).expect("binary"));
    let usage_line = reference
        .lines()
        .find(|line| line.starts_with("USAGE:"))
        .expect("usage line");
    assert!(
        err.contains(usage_line),
        "error help must use the same usage rendering as the help command:\n{err}"
    );

    // An unknown flag on an otherwise complete command line renders the
    // complete long reference `--help` prints, not a second, shorter menu.
    let ws = ws_path();
    let bad_flag = run_raw(&[
        "inspect-graph",
        ws.to_str().unwrap(),
        "--query",
        "os.system",
        "--trace",
    ])
    .expect("binary");
    assert_eq!(bad_flag.status.code(), Some(2), "unknown flag must exit 2");
    let err = stderr_of(&bad_flag);
    assert!(
        err.starts_with("error: unexpected argument '--trace'"),
        "unknown flag must lead with the themed error line:\n{err}"
    );
    assert!(
        err.contains(reference.trim()),
        "unknown flag output must embed the same long reference as `help inspect-graph`:\n--- error ---\n{err}\n--- reference ---\n{reference}"
    );
}

#[test]
fn tree_carries_module_connections() {
    let ws = ws_path();
    let Some(out) = run_raw(&["tree", ws.to_str().unwrap(), "--format", "json", "--all"]) else {
        return;
    };
    assert!(out.status.success(), "{}", stderr_of(&out));
    let value: serde_json::Value = serde_json::from_str(&stdout_of(&out)).expect("tree JSON");
    assert!(
        value["summary"]["total_cross_file_edges"].as_u64().unwrap_or(0) > 0,
        "tree must count cross-file call edges: {value:#}"
    );
    let files = value["roots"][0]["children"].as_array().expect("root children");
    let gateway = files
        .iter()
        .find(|node| node["name"] == "gateway.py")
        .expect("gateway.py node");
    let connections = &gateway["connections"];
    let resolved: Vec<&str> = connections["imports"]
        .as_array()
        .expect("imports")
        .iter()
        .flat_map(|import| import["resolved_files"].as_array().into_iter().flatten())
        .filter_map(|file| file.as_str())
        .collect();
    assert!(
        resolved.contains(&"user_service.py"),
        "`.user_service` must resolve to the workspace file: {connections:#}"
    );
    assert!(
        connections["calls_out"]
            .as_array()
            .is_some_and(|groups| groups.iter().any(|group| group["file"] == "user_service.py")),
        "gateway.py must list its resolved cross-file calls: {connections:#}"
    );
    let user_service = files
        .iter()
        .find(|node| node["name"] == "user_service.py")
        .expect("user_service.py node");
    assert!(
        user_service["connections"]["callers_in"]
            .as_array()
            .is_some_and(|groups| groups.iter().any(|group| group["file"] == "gateway.py")),
        "user_service.py must list gateway.py as a caller: {:#}",
        user_service["connections"]
    );

    let text = stdout_of(&run_raw(&["tree", ws.to_str().unwrap()]).expect("binary"));
    assert!(
        text.contains("→ user_service.py") && text.contains("← gateway.py"),
        "tree text must render the link lines:\n{text}"
    );
    let plain = run_raw(&["tree", ws.to_str().unwrap(), "--files-only", "--format", "json"]).expect("binary");
    let plain: serde_json::Value = serde_json::from_str(&stdout_of(&plain)).expect("plain tree JSON");
    assert!(
        plain["roots"][0]["children"]
            .as_array()
            .is_some_and(|nodes| nodes.iter().all(|node| node.get("connections").is_none())),
        "--files-only must skip compiler facts: {plain:#}"
    );
}

#[test]
fn read_file_renders_imports_and_cross_file_links() {
    let ws = ws_path();
    let Some(out) = run_raw(&[
        "read-file",
        ws.to_str().unwrap(),
        "gateway.py",
        "--format",
        "json",
    ]) else {
        return;
    };
    assert!(out.status.success(), "{}", stderr_of(&out));
    let value: serde_json::Value = serde_json::from_str(&stdout_of(&out)).expect("read-file JSON");
    let connections = &value["connections"];
    let imports = connections["imports"].as_array().expect("imports");
    let user_service_import = imports
        .iter()
        .find(|import| import["module"] == ".user_service")
        .expect("user_service import");
    assert_eq!(user_service_import["resolved_files"][0], "user_service.py");
    assert!(
        user_service_import["use_lines"]
            .as_array()
            .is_some_and(|lines| !lines.is_empty()),
        "import use lines must be recorded: {user_service_import:#}"
    );
    assert!(
        connections["calls_out"]
            .as_array()
            .is_some_and(|groups| groups.iter().any(|group| group["file"] == "user_service.py")),
        "read-file must list resolved cross-file calls: {connections:#}"
    );
    let kinds: Vec<&str> = value["marks"]
        .as_array()
        .expect("marks")
        .iter()
        .filter_map(|mark| mark["kind"].as_str())
        .collect();
    assert!(
        kinds.contains(&"call_out") && kinds.contains(&"import_use"),
        "marks must carry call-out and import-use entries: {kinds:?}"
    );

    let text = stdout_of(&run_raw(&["read-file", ws.to_str().unwrap(), "gateway.py"]).expect("binary"));
    assert!(
        text.contains("imports (") && text.contains("→ user_service.py") && text.contains("USES"),
        "read-file text must render imports, links, and use marks:\n{text}"
    );
}

#[test]
fn index_reports_the_workspace_context() {
    let ws = ws_path();
    let Some(out) = run_raw(&["index", ws.to_str().unwrap(), "--format", "json"]) else {
        return;
    };
    assert!(out.status.success(), "{}", stderr_of(&out));
    let value: serde_json::Value = serde_json::from_str(&stdout_of(&out)).expect("index JSON");
    let context = &value["context"];
    for key in [
        "module_roots",
        "dependency_roots",
        "generated_roots",
        "excluded_roots",
        "toolchain_manifests",
        "configured_source_variants",
        "source_transformations",
        "incomplete_reasons",
    ] {
        assert!(
            context[key].is_array(),
            "index context must carry `{key}`: {value:#}"
        );
    }
    let no_context = run_raw(&["context", ws.to_str().unwrap()]).expect("binary");
    assert_eq!(
        no_context.status.code(),
        Some(2),
        "the standalone context command is retired: {}",
        stderr_of(&no_context)
    );
}
