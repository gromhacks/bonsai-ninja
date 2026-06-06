//! End-to-end `security` command coverage on every lang's micro fixture.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn bin_path() -> Option<PathBuf> {
    if let Some(path) = option_env!("CARGO_BIN_EXE_bonsai-ninja") {
        return Some(PathBuf::from(path));
    }
    let debug = repo_root().join("target/debug/bonsai-ninja");
    if debug.exists() {
        return Some(debug);
    }
    let release = repo_root().join("target/release/bonsai-ninja");
    if release.exists() {
        return Some(release);
    }
    None
}

fn run(args: &[&str]) -> Option<String> {
    let bin = bin_path()?;
    // `--rules-dir` is now a per-subcommand flag, but the older tests
    // in this file pass it at the parent-`security` position
    // (`security <ws> --rules-dir <dir> <subcmd>`). Rewrite to
    // `security <ws> <subcmd> --rules-dir <dir> ...` by lifting the
    // pair out of its old slot and re-inserting it right after the
    // first positional argument that follows the workspace path.
    let mut rules_pair: Option<(&str, &str)> = None;
    let mut without: Vec<&str> = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--rules-dir" && i + 1 < args.len() {
            rules_pair = Some(("--rules-dir", args[i + 1]));
            i += 2;
            continue;
        }
        without.push(args[i]);
        i += 1;
    }
    let mut full: Vec<&str> = if let Some((flag, val)) = rules_pair {
        // Subcommand position: third element when args start with
        // ["security", <ws>, ...]. Insert the rules-dir pair right
        // AFTER the subcommand so clap's per-subcommand parser sees it.
        let mut v = without.clone();
        if v.len() >= 3 {
            v.insert(3, val);
            v.insert(3, flag);
        } else {
            v.push(flag);
            v.push(val);
        }
        v
    } else {
        without
    };
    full.push("--no-color");
    let out = Command::new(&bin)
        .args(&full)
        .env("COLUMNS", "200")
        .output()
        .expect("run bonsai-ninja");
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        panic!("args={args:?}\nstderr={stderr}\nstdout={stdout}");
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

fn rules_dir() -> String {
    repo_root()
        .join("security-patterns")
        .to_string_lossy()
        .into_owned()
}

fn enabled_rule_ids() -> &'static BTreeSet<String> {
    static ENABLED: OnceLock<BTreeSet<String>> = OnceLock::new();
    ENABLED.get_or_init(|| {
        let pack = bonsai_sdk::load_rulepack(&repo_root().join("security-patterns"))
            .expect("load rulepack for integration-test expectations");
        pack.all_rules()
            .into_iter()
            .filter(|rule| rule.enabled)
            .map(|rule| rule.id.clone())
            .collect()
    })
}

fn rule_is_enabled(rule_id: &str) -> bool {
    enabled_rule_ids().contains(rule_id)
}

fn micro_path(lang: &str) -> PathBuf {
    repo_root().join(format!("examples/{lang}/micro"))
}

fn mega_path(lang: &str) -> PathBuf {
    repo_root().join(format!("examples/{lang}/mega_flow"))
}

const MEGA_FLOW_LANGS: &[&str] = &[
    "c",
    "cpp",
    "csharp",
    "dart",
    "elixir",
    "erlang",
    "go",
    "java",
    "javascript",
    "kotlin",
    "lua",
    "objc",
    "perl",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "solidity",
    "swift",
    "typescript",
];

fn expected_mega_chain_hops(lang: &str) -> &'static [&'static str] {
    match lang {
        "c" | "cpp" | "elixir" => &["main", "orchestrate", "persist", "run"],
        "csharp" => &["Handle", "Orchestrate", "Persist", "Run", "Execute"],
        "dart" | "javascript" | "lua" | "perl" | "php" | "ruby" | "swift" | "typescript" => {
            &["handle_request", "orchestrate", "persist", "run", "execute"]
        }
        "erlang" => &["orchestrate", "persist", "run", "execute"],
        "objc" => &["handle_request", "orchestrate", "persist", "run", "executeCmd"],
        "go" => &["handleRequest", "Orchestrate", "Persist", "Run", "Execute"],
        "java" | "kotlin" | "scala" => &["handle", "orchestrate", "persist", "run", "execute"],
        "rust" => &["persist", "run", "execute"],
        "python" => &[
            "handle_request",
            "run_pipeline",
            "orchestrate",
            "persist",
            "perform",
            "execute",
        ],
        "solidity" => &["handle", "orchestrate", "persist"],
        _ => &[],
    }
}

fn expected_mega_finding_count_with_inferred_sources(lang: &str) -> usize {
    // Mirrors security_pipeline_regressions.rs
    // `expected_mega_flow_findings_with_inferred_sources` and
    // scripts/validate-mega-cli.py `EXPECTED_FINDINGS`. Refreshed
    // 2026-05-29: FN-language gaps closed (cpp/csharp/dart/elixir/java/
    // scala 0→1, php 0→2); swift settled at 1 once the redundant
    // inferred-source over-claim was filtered; go 2→1 + objc 2→1
    // (redundant-inferred / xxe over-claim removed); python 5→2 and
    // dart→1 (combiner group_id+sink-site dedup collapsed duplicate
    // entry-chain rows, including local inferred callable-object
    // evidence); erlang 2→1 and solidity 3→2 once equivalent
    // inferred/member paths are grouped into one real report row.
    match lang {
        "c" => 1,
        "cpp" => 1,
        "csharp" => 1,
        "dart" => 1,
        "elixir" => 1,
        "erlang" => 1,
        "go" => 1,
        "java" => 1,
        "javascript" => 1,
        "kotlin" => 1,
        "lua" => 1,
        "objc" => 1,
        "perl" => 1,
        "php" => 2,
        "python" => 2,
        "ruby" => 2,
        "rust" => 1,
        "scala" => 1,
        "solidity" => 2,
        "swift" => 1,
        "typescript" => 1,
        other => panic!("missing mega_flow expected finding count for {other}"),
    }
}

fn chain_contains_hop(chain: &[&str], hop: &str) -> bool {
    chain
        .iter()
        .any(|step| *step == hop || step.strip_prefix(hop).is_some_and(|rest| rest.starts_with('@')))
}

fn mega_entry_symbol(lang: &str) -> &'static str {
    match lang {
        "c" | "cpp" | "elixir" => "main",
        "csharp" => "Handle",
        "go" => "handleRequest",
        "java" | "kotlin" | "scala" | "solidity" => "handle",
        _ => "handle_request",
    }
}

fn mega_target_symbol(lang: &str) -> &'static str {
    match lang {
        "csharp" | "go" => "Execute",
        "objc" => "executeCmd",
        "solidity" => "persist",
        _ => "execute",
    }
}

fn required_mega_construct_markers(lang: &str) -> &'static [&'static str] {
    match lang {
        "c" => &[
            "#include",
            "struct Envelope",
            "enum Kind",
            "typedef void (*joiner_fn)",
            "char *",
            "char buffer",
            "[512]",
            "while (",
            "if (",
            "switch (",
            "goto ",
            "do {",
            "for (",
            "break;",
            "continue;",
            "strncpy",
            "strncat",
        ],
        "cpp" => &[
            "#include",
            "using TokenList",
            "class AuditedRepository",
            "virtual",
            "template <",
            "std::function",
            "return [sep]",
            "while (",
            "auto [",
            "for (const",
            "std::accumulate",
            "if (",
            "switch (",
            "try {",
            "catch (",
            "return persist",
        ],
        "csharp" => &[
            "using System",
            "using Tasks =",
            "using static",
            "record Envelope",
            "Tuple<",
            "ValueTuple",
            "=>",
            "Func<",
            "async Tasks.Task",
            "await ",
            "yield return",
            ".Select(",
            ".Aggregate(",
            "switch",
            "try",
            "catch",
            "finally",
            "using (",
            "abstract class",
            "override",
        ],
        "dart" => &[
            "import ",
            " as store",
            "Future<void>",
            "await ",
            "sync*",
            "async*",
            "yield",
            "?.",
            "..",
            "extension ",
            "String Function",
            ".fold<",
            "switch (",
            "try",
            "catch",
            "finally",
            "mixin Auditable",
            "abstract class",
            "factory Repository.wrap",
        ],
        "elixir" => &[
            "alias ",
            "as: Store",
            "import ",
            "require ",
            "use ",
            "|>",
            "defstruct",
            "defp route(:run, joined) when",
            "fn",
            "&",
            "Enum.",
            "Stream.",
            "case ",
            "cond do",
            "for part <-",
            "try do",
            "rescue",
            "with ",
        ],
        "erlang" => &[
            "-include",
            "-record",
            "-import(storage",
            "when",
            "fun(",
            "[Part ||",
            "lists:map",
            "lists:filter",
            "lists:foldl",
            "case ",
            "receive",
            "try",
            "catch",
            "->",
        ],
        "go" => &[
            "import (",
            "type Envelope struct",
            "execpkg \"os/exec\"",
            "struct {",
            "interface",
            "func (",
            "...string",
            "makeJoiner",
            "go func",
            "chan string",
            "defer",
            "select",
            "context.Context",
            "for tok := range",
            "panic",
            "recover",
            "switch k :=",
            "switch env.Kind",
            "if ",
            "for ",
            "range",
        ],
        "java" => &[
            "package mega",
            "record Envelope",
            "import static",
            "<String>",
            "var ",
            "Optional.ofNullable",
            "Arrays.stream",
            "::",
            "->",
            "interface",
            "for (",
            "while (",
            "switch (",
            "try (",
            "catch",
            "finally",
            "abstract class",
            "extends",
            "class AuditedRepository",
        ],
        "javascript" => &[
            "require(\"./storage\")",
            "persist: persistEnvelope",
            "import(\"./storage\")",
            "async function",
            "await ",
            "Promise",
            "function*",
            "async function*",
            "for await",
            "...rest",
            "?.",
            "??",
            ".flatMap(",
            "switch (",
            "try",
            "catch",
            "finally",
            "class AuditedRepository",
            "extends",
            "super",
            ".map(",
            ".filter(",
            ".reduce(",
        ],
        "kotlin" => &[
            "import ",
            "data class Envelope",
            "typealias RepoEnvelope",
            "sealed class",
            "?.",
            "?:",
            "fun String.canonical",
            "{ acc, tok ->",
            "splitToSequence",
            ".fold",
            "let",
            "apply",
            "when (",
            "runCatching",
            "try",
            "catch",
            "abstract class",
            "companion object",
            "override",
        ],
        "lua" => &[
            "require(\"storage\")",
            "local Storage",
            "{ ... }",
            "return envelope.cmd, envelope.user",
            "coroutine.wrap",
            "function(acc, tok)",
            "for word in",
            "for i = 1",
            "if ",
            "pcall(function",
            "routes =",
            "setmetatable",
            ":gsub",
        ],
        "objc" => &[
            "#import",
            "@interface",
            "@implementation",
            "@protocol",
            "@property",
            "@{",
            "@[",
            "typedef NSString *",
            "for (NSString *",
            "enumerateObjectsUsingBlock",
            "@try",
            "@catch",
            "@finally",
            "super",
        ],
        "perl" => &[
            "use ",
            "require",
            "package ",
            "my $",
            "{",
            "[",
            "sub {",
            "sub StorePersist",
            "for my",
            "map",
            "grep",
            "sort",
            "unless",
            "?",
            "s/",
            "eval {",
            "exists $routes",
            "wantarray",
        ],
        "php" => &[
            "require_once",
            "trait Loggable",
            "use Storage as Store",
            "array",
            "list(",
            "...$",
            "yield",
            "fn(",
            "function (",
            "foreach",
            "array_map",
            "array_filter",
            "array_reduce",
            "match (",
            "try",
            "catch",
            "finally",
            "abstract class",
            "interface Runnable",
        ],
        "python" => &[
            "import ",
            "from ",
            " as ",
            "@auditable",
            "as audit_route",
            "as run_orchestrate",
            "def wrapper",
            "async def",
            "await ",
            "async for",
            "yield",
            "yield from",
            "for ",
            "[p for",
            "{k:",
            "match ",
            "case ",
            "with Transaction",
            "@property",
            "@classmethod",
            "@staticmethod",
            "__call__",
            "class CommandRunner",
            "super()",
            "functools.partial",
            "*args",
            "**kwargs",
        ],
        "ruby" => &[
            "require_relative",
            "Store = Storage",
            "module ",
            "include",
            "class AuditedRepository",
            "< Repository",
            "yield part",
            "->(sep)",
            "Proc",
            "*",
            "**",
            "&block",
            ".inject",
            "&JOINER",
            ".map",
            ".reject",
            "&.",
            "case envelope",
            "in {",
            "begin",
            "rescue",
            "ensure",
            "<<~",
        ],
        "rust" => &[
            "mod ",
            "storage as store",
            "type CmdText",
            "pub struct Envelope",
            "pub enum Kind",
            "pub trait",
            "impl Runnable",
            "impl",
            "<",
            "Box<dyn Fn",
            "|acc",
            ".map",
            ".filter",
            ".fold",
            "Option",
            "Result<",
            "?",
            "match envelope.kind",
            "if let",
            "while let",
            "Result<Envelope",
            "unwrap_or_else",
        ],
        "scala" => &[
            "package ",
            "as Store",
            "enum Kind",
            "case class Envelope",
            "trait ",
            "abstract class",
            "extends",
            "override",
            "makeJoiner(sep: String)(acc",
            "=>",
            "for value <-",
            "lazy val",
            "Option",
            "Try {",
            "match {",
            "foldLeft",
            "case Success",
        ],
        "solidity" => &[
            "modifier audit",
            "as FlowPipeline",
            "as Store",
            "contract ",
            "is ",
            "event ",
            "enum Kind",
            "struct Envelope",
            "mapping(",
            "calldata",
            "memory",
            "storage",
            "library",
            "if (kind",
            "for (uint256",
            "unchecked",
            "try store.persist",
            "catch",
            "mapping(bytes => bool)",
        ],
        "swift" => &[
            "import Foundation",
            "enum Kind",
            "typealias RepoEnvelope",
            "struct Envelope",
            "class AuditedRepository",
            "protocol Runnable",
            "override",
            "static func passthrough<T>",
            "guard let",
            "if let",
            ".reduce",
            ".map",
            ".filter",
            "switch envelope.kind",
            "do {",
            "try",
            "catch",
            "defer {",
        ],
        "typescript" => &[
            "import { persist as persistEnvelope",
            "export interface Envelope",
            "type Action",
            "<",
            "a is Extract",
            "enum Kind",
            "async function",
            "await ",
            "for await",
            "function*",
            "async function*",
            "...rest",
            "?.",
            "??",
            "class AuditedRepository",
            "abstract class",
            "extends",
            "super",
            ".flatMap(",
            ".map(",
            ".filter(",
            ".reduce(",
            "switch",
            "try",
            "catch",
            "finally",
            "abstract class",
        ],
        _ => &[],
    }
}

fn required_mega_flow_event_kinds(lang: &str) -> &'static [&'static str] {
    match lang {
        "c" => &["Assign", "Branch", "Call", "Loop", "Return"],
        "cpp" => &["Assign", "Branch", "Call", "Loop", "Return", "Try"],
        "csharp" => &["Assign", "Await", "Branch", "Call", "Loop", "Return", "Using"],
        "dart" => &["Assign", "Await", "Branch", "Call", "Loop", "Return", "Try"],
        "elixir" => &["Assign", "Call"],
        "erlang" => &["Assign", "Branch", "Call", "Try", "Using"],
        "go" => &["Assign", "Branch", "Call", "Defer", "Loop", "Return"],
        "java" => &["Assign", "Branch", "Call", "Loop", "Return", "Try"],
        "javascript" => &["Assign", "Await", "Branch", "Call", "Loop", "Return", "Try"],
        "kotlin" => &["Assign", "Branch", "Call", "Return", "Try"],
        "lua" => &["Assign", "Branch", "Call", "Loop", "Return"],
        "objc" => &["Assign", "Branch", "Call", "Loop", "Return", "Try"],
        "perl" => &["Assign", "Branch", "Call", "Loop", "Return"],
        "php" => &["Assign", "Branch", "Call", "Loop", "Return", "Try"],
        "python" => &[
            "Assign", "Branch", "Call", "Loop", "Return", "Try", "Using", "Yield",
        ],
        "ruby" => &["Assign", "Call", "Continue", "Try", "Yield"],
        "rust" => &["Assign", "Branch", "Call", "Loop"],
        "scala" => &["Assign", "Branch", "Call"],
        "solidity" => &["Assign", "Branch", "Call", "Loop", "Return", "Try"],
        "swift" => &["Assign", "Branch", "Call", "Loop", "Return"],
        "typescript" => &["Assign", "Await", "Branch", "Call", "Loop", "Return", "Try"],
        _ => &[],
    }
}

fn mega_flow_requires_alias_map(lang: &str) -> bool {
    matches!(
        lang,
        "csharp"
            | "dart"
            | "elixir"
            | "go"
            | "javascript"
            | "lua"
            | "php"
            | "python"
            | "rust"
            | "solidity"
            | "typescript"
    )
}

fn collect_flow_event_kinds(value: &serde_json::Value, out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(obj) => {
            if obj.len() == 1 {
                if let Some(kind) = obj.keys().next().filter(|kind| is_flow_event_kind(kind)) {
                    out.insert(kind.clone());
                }
            }
            if let Some(events) = obj.get("flow_events").and_then(|v| v.as_array()) {
                for event in events {
                    if let Some(kind) = event.as_object().and_then(|o| o.keys().next()) {
                        out.insert(kind.clone());
                    }
                }
            }
            for child in obj.values() {
                collect_flow_event_kinds(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_flow_event_kinds(item, out);
            }
        }
        _ => {}
    }
}

fn is_flow_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        "Assign"
            | "Await"
            | "Branch"
            | "Break"
            | "Call"
            | "Continue"
            | "Defer"
            | "Lifecycle"
            | "Loop"
            | "Return"
            | "Throw"
            | "Try"
            | "Using"
            | "Yield"
    )
}

fn collect_rule_ids(value: &serde_json::Value, out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(obj) => {
            if let Some(rule_id) = obj.get("rule_id").and_then(|v| v.as_str()) {
                out.insert(rule_id.to_string());
            }
            for child in obj.values() {
                collect_rule_ids(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_rule_ids(item, out);
            }
        }
        _ => {}
    }
}

fn export_array_len(export: &serde_json::Value, path: &[&str]) -> usize {
    let mut value = export;
    for key in path {
        value = &value[*key];
    }
    value.as_array().map_or(0, Vec::len)
}

fn reachable_fact_kind_count(export: &serde_json::Value, kind: &str) -> usize {
    export["taint_graph"]["reachable_facts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|fact| fact["by_kind"][kind].as_array())
        .map(Vec::len)
        .sum()
}

fn alias_map_entry_count(export: &serde_json::Value) -> usize {
    export["taint_graph"]["alias_maps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|map| map["entries"].as_array())
        .map(Vec::len)
        .sum()
}

fn read_fixture_text(path: &std::path::Path) -> String {
    let mut text = String::new();
    let entries = std::fs::read_dir(path).expect("read fixture dir");
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.components().any(|c| c.as_os_str() == ".bonsai") {
            continue;
        }
        if path.is_dir() {
            text.push_str(&read_fixture_text(&path));
        } else if path.is_file() {
            text.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
            text.push('\n');
        }
    }
    text
}

fn temp_workspace(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let base = std::env::temp_dir();
    for attempt in 0..100 {
        let path = base.join(format!(
            "bonsai-security-{tag}-{}-{nanos}-{attempt}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create temp workspace {}: {e}", path.display()),
        }
    }
    panic!("could not allocate temp workspace for {tag}");
}

#[test]
fn json_stdout_stays_clean_when_sidecars_are_stale() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = temp_workspace("stale-sidecar-json");
    std::fs::write(
        ws.join("main.rs"),
        r#"
use std::env;
use std::process::Command;

fn main() {
    let cmd = env::var("CMD").unwrap();
    Command::new(cmd).status().ok();
}
"#,
    )
    .expect("write rust fixture");
    let bonsai = ws.join(".bonsai");
    std::fs::create_dir_all(&bonsai).expect("create .bonsai dir");
    std::fs::write(bonsai.join("dataflow.v3.factstore"), b"not a factstore").expect("write dataflow sidecar");
    std::fs::write(bonsai.join("value_flow.v3.factstore"), b"not a factstore")
        .expect("write value-flow sidecar");

    let out = Command::new(&bin)
        .args([
            "security",
            ws.to_str().unwrap(),
            "taint-analysis",
            "--rules-dir",
            &rules_dir(),
            "--format",
            "json",
            "--all",
            "--no-color",
            "--no-progress",
        ])
        .env("RUST_LOG", "warn")
        .output()
        .expect("run bonsai-ninja");
    assert!(
        out.status.success(),
        "taint-analysis failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ignoring stale or corrupt"),
        "test fixture should exercise stale sidecar warning path, got stderr:\n{stderr}"
    );
    serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout must be a single valid JSON document even when warnings are emitted: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            stderr
        )
    });
}

#[test]
fn sources_enumerate_for_python() {
    let ws = micro_path("python");
    if !ws.exists() {
        return;
    }
    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "sources",
    ])
    .unwrap();
    assert!(out.contains("python.flask"), "got:\n{out}");
}

#[test]
fn sinks_enumerate_for_python() {
    let ws = micro_path("python");
    if !ws.exists() {
        return;
    }
    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "sinks",
    ])
    .unwrap();
    assert!(out.contains("python.cmdi.os_system"), "got:\n{out}");
}

#[test]
fn taint_analysis_produces_findings_for_python() {
    let ws = micro_path("python");
    if !ws.exists() {
        return;
    }
    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--source",
        "^python\\.flask\\.",
        "--trust",
        "remote",
        "--sink",
        "^python\\.cmdi\\.",
    ])
    .unwrap();
    assert!(out.contains("S:"), "expected S: finding id in output:\n{out}");
    assert!(out.contains("python.cmdi.os_system"), "got:\n{out}");
}

#[test]
fn taint_analysis_does_not_report_reachable_but_untainted_sink() {
    let ws = temp_workspace("overreach");
    std::fs::write(
        ws.join("app.py"),
        r#"
import os
from flask import request

def handle():
    cmd = request.args.get("cmd")
    safe()
    return cmd

def safe():
    os.system("echo constant")
"#,
    )
    .expect("write fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--source",
        "^python\\.flask\\.request_args$",
        "--sink",
        "^python\\.cmdi\\.os_system$",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    assert!(
        !out.contains("\"finding_id\""),
        "reachable clean sink must not become a taint finding:\n{out}"
    );
}

#[test]
fn taint_analysis_source_filter_excludes_pattern_only_findings() {
    let ws = temp_workspace("source-filter-pattern-only");
    std::fs::write(
        ws.join("app.py"),
        r#"
import hashlib

def handle():
    return hashlib.md5(b"constant")
"#,
    )
    .expect("write fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--source",
        "^python\\.flask\\.",
        "--sink",
        "^python\\.crypto\\.hashlib_md5$",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("taint JSON");
    assert_eq!(
        parsed.as_array().map(Vec::len),
        Some(0),
        "source-filtered taint run must not include source-less pattern findings:\n{out}"
    );
}

#[test]
fn taint_analysis_sarif_includes_source_independent_api_misuse_by_default() {
    let ws = temp_workspace("sarif-source-independent");
    std::fs::write(
        ws.join("App.java"),
        r#"
import java.security.MessageDigest;

class App {
    void handle() throws Exception {
        MessageDigest.getInstance("MD5");
    }
}
"#,
    )
    .expect("write fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--format",
        "sarif",
    ])
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("sarif JSON");
    let results = parsed["runs"][0]["results"]
        .as_array()
        .expect("SARIF results array");
    let md5 = results
        .iter()
        .find(|result| result["ruleId"] == "java.crypto.md5_digest")
        .unwrap_or_else(|| panic!("SARIF must include source-independent MD5 API misuse:\n{out}"));
    assert!(
        md5["codeFlows"].is_null(),
        "source-independent SARIF result must not fabricate a taint codeFlow:\n{md5:#}"
    );
    assert_eq!(
        md5["properties"]["bonsai"]["source_rule_id"],
        "pattern:java.crypto.md5_digest"
    );
}

#[test]
fn taint_analysis_sarif_includes_java_owasp_api_misuse_without_fake_flows() {
    let ws = temp_workspace("sarif-java-owasp-api-misuse");
    std::fs::write(
        ws.join("App.java"),
        r#"
import java.security.MessageDigest;
import java.util.Random;

class App {
    void handle() throws Exception {
        MessageDigest.getInstance("SHA-1");
        new Random();
        Math.random();
    }
}
"#,
    )
    .expect("write fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--format",
        "sarif",
    ])
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("sarif JSON");
    let results = parsed["runs"][0]["results"]
        .as_array()
        .expect("SARIF results array");
    for rule_id in [
        "java.hash.messagedigest_sha1",
        "java.crypto.random_ctor",
        "java.crypto.math_random",
    ] {
        let result = results
            .iter()
            .find(|result| result["ruleId"] == rule_id)
            .unwrap_or_else(|| panic!("SARIF must include Java OWASP API misuse {rule_id}:\n{out}"));
        assert!(
            result["codeFlows"].is_null(),
            "source-independent SARIF result must not fabricate a taint codeFlow:\n{result:#}"
        );
        assert_eq!(
            result["properties"]["bonsai"]["source_rule_id"],
            format!("pattern:{rule_id}")
        );
    }
}

#[test]
fn taint_analysis_still_reports_same_function_tainted_sink_arg() {
    let ws = temp_workspace("direct-taint");
    std::fs::write(
        ws.join("app.py"),
        r#"
import os
from flask import request

def handle():
    cmd = request.args.get("cmd")
    os.system("echo " + cmd)
"#,
    )
    .expect("write fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--source",
        "^python\\.flask\\.request_args$",
        "--sink",
        "^python\\.cmdi\\.os_system$",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    assert!(
        out.contains("\"finding_id\""),
        "tainted sink arg should still report a finding:\n{out}"
    );
}

#[test]
fn taint_analysis_uses_exact_source_seed_not_every_parameter() {
    let ws = temp_workspace("source-seed");
    let rules = ws.join("security-patterns");
    let source_dir = rules.join("langs/python/sources");
    let sink_dir = rules.join("langs/python/sinks");
    std::fs::create_dir_all(&source_dir).expect("source rule dir");
    std::fs::create_dir_all(&sink_dir).expect("sink rule dir");
    std::fs::write(
        source_dir.join("params.yml"),
        r"- id: python.test.user_param
  enabled: true
  trust: remote
  tag: http-input
  match:
    kind: param
    target:
      name: user
  description: Test-only user parameter source.
",
    )
    .expect("write source rule");
    std::fs::write(
        sink_dir.join("cmd.yml"),
        r"- id: python.test.os_system
  enabled: true
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: Test-only os.system sink.
",
    )
    .expect("write sink rule");
    std::fs::write(
        ws.join("bad.py"),
        r"
import os

def handle_bad(user, safe):
    os.system(user)
",
    )
    .expect("write positive fixture");
    std::fs::write(
        ws.join("clean.py"),
        r"
import os

def handle_clean(user, safe):
    os.system(safe)
",
    )
    .expect("write negative fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        rules.to_str().unwrap(),
        "taint-analysis",
        "--source",
        "^python\\.test\\.user_param$",
        "--sink",
        "^python\\.test\\.os_system$",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    assert!(out.contains("bad.py"), "tainted user param should report:\n{out}");
    assert!(
        !out.contains("clean.py"),
        "clean sibling parameter must not inherit source taint:\n{out}"
    );
}

#[test]
fn taint_analysis_text_numbers_actual_taint_steps() {
    let ws = temp_workspace("taint-step-render");
    let rules = ws.join("security-patterns");
    let source_dir = rules.join("langs/python/sources");
    let sink_dir = rules.join("langs/python/sinks");
    std::fs::create_dir_all(&source_dir).expect("source rule dir");
    std::fs::create_dir_all(&sink_dir).expect("sink rule dir");
    std::fs::write(
        source_dir.join("params.yml"),
        r"- id: python.test.user_param
  enabled: true
  trust: remote
  tag: http-input
  match:
    kind: param
    target:
      name: user
  description: Test-only user parameter source.
",
    )
    .expect("write source rule");
    std::fs::write(
        sink_dir.join("cmd.yml"),
        r"- id: python.test.os_system
  enabled: true
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: Test-only os.system sink.
",
    )
    .expect("write sink rule");
    std::fs::write(
        ws.join("app.py"),
        r"
import os

def handle(user):
    return run(user)

def run(cmd):
    return os.system(cmd)
",
    )
    .expect("write fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        rules.to_str().unwrap(),
        "taint-analysis",
        "--source",
        "^python\\.test\\.user_param$",
        "--sink",
        "^python\\.test\\.os_system$",
        "--no-compact",
        "--context",
        "all",
    ])
    .unwrap();

    let source = out
        .find("[TAINT FLOW 1 SOURCE: python.test.user_param")
        .expect("missing source taint annotation");
    let taint = out
        .find("[TAINT FLOW 1 TAINT: handle -> run arg[0] user -> cmd]")
        .expect("missing arg-preserving taint annotation");
    let sink = out
        .find("[TAINT FLOW 1 SINK: python.test.os_system arg[0] cmd]")
        .expect("missing sink arg annotation");
    assert!(
        source < taint && taint < sink,
        "taint annotations should render in source -> propagation -> sink order:\n{out}"
    );
}

#[test]
fn taint_analysis_preserves_multiple_same_rule_sink_sites_in_grouped_json() {
    let ws = temp_workspace("same-rule-sinks");
    std::fs::write(
        ws.join("app.py"),
        r#"
import os
from flask import request

def handle():
    cmd = request.args.get("cmd")
    os.system(cmd)
    os.system(cmd + " --again")
"#,
    )
    .expect("write fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--source",
        "^python\\.flask\\.request_args$",
        "--sink",
        "^python\\.cmdi\\.os_system$",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("taint-analysis JSON");
    let rows = parsed.as_array().expect("finding array");
    assert_eq!(
        rows.len(),
        2,
        "arg-aware taint paths should keep same-rule sink sites as distinct findings:\n{out}"
    );
    let mut sink_lines: Vec<u64> = rows
        .iter()
        .filter_map(|row| row["sink"]["line"].as_u64())
        .collect();
    sink_lines.sort_unstable();
    assert_eq!(
        sink_lines,
        vec![7, 8],
        "both os.system sink sites should be preserved as first-class findings:\n{out}"
    );
    let flow_ids: std::collections::HashSet<_> = rows
        .iter()
        .filter_map(|row| row["representative_flow_id"].as_str())
        .collect();
    assert_eq!(
        flow_ids.len(),
        2,
        "distinct sink call sites should carry distinct representative flow ids:\n{out}"
    );
}

#[test]
fn taint_analysis_does_not_treat_source_lookup_key_literal_as_tainted() {
    let ws = temp_workspace("lookup-key-literal");
    std::fs::write(
        ws.join("app.py"),
        r#"
import os
from flask import request

def handle():
    cmd = request.args.get("cmd")
    os.system("cmd")
"#,
    )
    .expect("write fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--source",
        "^python\\.flask\\.request_args$",
        "--sink",
        "^python\\.cmdi\\.os_system$",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    assert!(
        !out.contains("\"finding_id\""),
        "literal lookup keys must not taint identical string literals at sinks:\n{out}"
    );
}

#[test]
fn taint_analysis_does_not_report_after_clean_reassignment_in_callee() {
    let ws = temp_workspace("callee-clean-reassign");
    std::fs::write(
        ws.join("app.py"),
        r#"
import os
from flask import request

def handle():
    cmd = request.args.get("cmd")
    run(cmd)

def run(cmd):
    cmd = "constant"
    os.system(cmd)
"#,
    )
    .expect("write fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--source",
        "^python\\.flask\\.request_args$",
        "--sink",
        "^python\\.cmdi\\.os_system$",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    assert!(
        !out.contains("\"finding_id\""),
        "clean reassignment in callee must kill stale taint before sink:\n{out}"
    );
}

#[test]
fn c_mega_flow_renders_precise_command_sink_chain() {
    let ws = mega_path("c");
    if !ws.exists() {
        return;
    }
    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--all",
        "--context",
        "32k",
    ])
    .unwrap();
    assert!(
        out.contains("SOURCE:  c.input.argv_param") && out.contains("main → orchestrate"),
        "C argv source should propagate out of main through adapter-derived side effects:\n{out}"
    );
    assert!(
        out.contains("main → orchestrate → persist → run → execute"),
        "C command-injection finding should render the real source-to-sink chain:\n{out}"
    );
    assert!(
        !out.contains("in joiner_impl\n    —  [trust=local · tag=entry-point"),
        "address-taken helper must not be reported as a standalone inferred entrypoint:\n{out}"
    );
}

#[test]
fn source_analysis_maps_python_entrypoint_paths() {
    let ws = micro_path("python");
    if !ws.exists() {
        return;
    }
    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "source-analysis",
        "--source",
        "^python\\.flask\\.",
        "--trust",
        "remote",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    assert!(out.contains("\"source\""), "expected source metadata:\n{out}");
    assert!(out.contains("\"flow\""), "expected rendered source flow:\n{out}");
    assert!(out.contains("python.flask"), "got:\n{out}");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("source-analysis JSON");
    let rows = parsed.as_array().expect("source-analysis rows");
    assert!(
        rows.iter()
            .all(|row| row["analysis_complete"].as_bool().is_some()),
        "source-analysis rows must expose machine-readable completeness:\n{out}"
    );
    assert!(
        rows.iter()
            .all(|row| row["analysis_incomplete_reasons"].as_array().is_some()),
        "source-analysis rows must expose machine-readable incomplete reasons:\n{out}"
    );
    assert!(
        rows.iter().all(|row| row["lineage"].is_object()),
        "source-analysis rows must include lineage status:\n{out}"
    );
    assert!(
        rows.iter()
            .all(|row| row["analysis_complete"].as_bool() == Some(true)),
        "source-analysis --all must request uncapped lineage evidence for this fixture:\n{out}"
    );
    assert!(
        rows.iter().all(|row| {
            row["analysis_incomplete_reasons"]
                .as_array()
                .is_some_and(Vec::is_empty)
        }),
        "complete source-analysis --all rows must not carry incomplete reasons:\n{out}"
    );
    let multi_hop_precisions: Vec<_> = rows
        .iter()
        .filter(|row| {
            row["flow"]["chain"]
                .as_array()
                .is_some_and(|chain| chain.len() > 1)
        })
        .filter_map(|row| row["flow"]["precision"].as_str())
        .collect();
    assert!(
        !multi_hop_precisions.is_empty(),
        "fixture should expose source flows crossing call edges:\n{out}"
    );
    assert!(
        multi_hop_precisions.iter().all(|precision| *precision == "narrowed"),
        "source-analysis flow precision must reflect lineage call-edge precision, got {multi_hop_precisions:?}:\n{out}"
    );
}

#[test]
fn source_analysis_rejects_sarif_format_instead_of_emitting_json() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = micro_path("python");
    if !ws.exists() {
        return;
    }
    let out = Command::new(&bin)
        .args([
            "security",
            ws.to_str().unwrap(),
            "source-analysis",
            "--rules-dir",
            &rules_dir(),
            "--format",
            "sarif",
            "--all",
            "--no-color",
        ])
        .output()
        .expect("run bonsai-ninja");
    assert!(
        !out.status.success(),
        "source-analysis --format sarif should fail rather than emit non-SARIF JSON"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not emit SARIF"),
        "error should explain SARIF support boundary, got:\n{stderr}"
    );
}

#[test]
fn source_analysis_paged_json_exposes_top_level_completeness() {
    let ws = micro_path("python");
    if !ws.exists() {
        return;
    }
    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "source-analysis",
        "--source",
        "^python\\.flask\\.",
        "--trust",
        "remote",
        "--format",
        "json",
        "--context",
        "1",
    ])
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("source-analysis JSON");
    assert!(
        parsed["rows"].as_array().is_some(),
        "paged source-analysis JSON must use wrapped rows shape:\n{out}"
    );
    assert_eq!(
        parsed["analysis_complete"].as_bool(),
        Some(false),
        "paged source-analysis JSON must not claim complete row coverage:\n{out}"
    );
    let reasons = parsed["analysis_incomplete_reasons"]
        .as_array()
        .expect("analysis_incomplete_reasons array");
    assert!(
        reasons.iter().any(|reason| {
            reason
                .as_str()
                .is_some_and(|reason| reason.contains("paged security/source-analysis result incomplete"))
        }),
        "paged source-analysis JSON must explain incomplete row coverage:\n{out}"
    );
}

#[test]
fn taint_analysis_json_exposes_completion_metadata() {
    let ws = micro_path("python");
    if !ws.exists() {
        return;
    }
    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--source",
        "^python\\.flask\\.",
        "--trust",
        "remote",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("taint-analysis JSON");
    let rows = parsed.as_array().expect("taint-analysis rows");
    assert!(!rows.is_empty(), "fixture should emit taint findings:\n{out}");
    assert!(
        rows.iter()
            .all(|row| row["analysis_complete"].as_bool() == Some(true)),
        "taint-analysis findings must expose complete semantic evidence:\n{out}"
    );
    assert!(
        rows.iter().all(|row| row["analysis_incomplete_reasons"]
            .as_array()
            .is_some_and(Vec::is_empty)),
        "taint-analysis findings must expose empty incomplete reasons when complete:\n{out}"
    );
}

#[test]
fn taint_analysis_rejects_broad_precision() {
    let Some(bin) = bin_path() else {
        return;
    };
    let ws = micro_path("python");
    if !ws.exists() {
        return;
    }
    let out = Command::new(&bin)
        .args([
            "security",
            ws.to_str().unwrap(),
            "taint-analysis",
            "--rules-dir",
            &rules_dir(),
            "--precision",
            "over-approximate",
            "--no-color",
            "--no-progress",
        ])
        .output()
        .expect("run bonsai-ninja");
    assert!(
        !out.status.success(),
        "taint-analysis --precision over-approximate should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("semantic-only"),
        "error should explain semantic-only precision, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("ignoring stale or corrupt"),
        "precision validation should run before workspace sidecar loading, got:\n{stderr}"
    );
}

#[test]
fn source_analysis_does_not_follow_untainted_downstream_call() {
    let ws = temp_workspace("source-overreach");
    std::fs::write(
        ws.join("app.py"),
        r#"
import os
from flask import request

def handle():
    cmd = request.args.get("cmd")
    safe()
    return cmd

def safe():
    os.system("echo constant")
"#,
    )
    .expect("write fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "source-analysis",
        "--source",
        "^python\\.flask\\.request_args$",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("source-analysis JSON");
    let text = parsed.to_string();
    assert!(
        !text.contains("\"safe\""),
        "source-analysis must not follow clean downstream calls:\n{out}"
    );
}

#[test]
fn taint_analysis_run_across_every_micro_lang() {
    // One smoke-test per language. Skips gracefully if a micro
    // fixture doesn't exist for a given adapter.
    for lang in MEGA_FLOW_LANGS {
        let ws = micro_path(lang);
        if !ws.exists() {
            continue;
        }
        // Just verify the command doesn't panic and produces a
        // report header. Finding counts are covered by the per-lang
        // smoke scripts in CONTRIBUTING; we don't pin them here
        // because rulepacks evolve.
        let out = run(&[
            "security",
            ws.to_str().unwrap(),
            "--rules-dir",
            &rules_dir(),
            "taint-analysis",
        ])
        .unwrap();
        assert!(
            out.contains("finding(s)"),
            "{lang}: expected report header in output:\n{out}"
        );
    }
}

#[test]
fn taint_analysis_run_across_every_mega_flow_lang() {
    for lang in MEGA_FLOW_LANGS {
        let ws = mega_path(lang);
        if !ws.exists() {
            continue;
        }
        let out = run(&[
            "security",
            ws.to_str().unwrap(),
            "--rules-dir",
            &rules_dir(),
            "taint-analysis",
            // Inferred entry-point sources are CLI-opt-in (commit
            // 1f4922c). The expected counts in expected_mega_finding_count
            // were authored against the inferred-on surface.
            "--inferred-sources",
            "--format",
            "json",
            "--all",
        ])
        .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&out).unwrap_or_else(|e| panic!("{lang}: invalid JSON: {e}\n{out}"));
        assert!(parsed.is_array(), "{lang}: expected JSON array:\n{out}");
        let rows = parsed.as_array().expect("array");
        let expected_count = expected_mega_finding_count_with_inferred_sources(lang);
        assert_eq!(
            rows.len(),
            expected_count,
            "{lang}: unexpected mega_flow inferred-source finding count:\n{out}"
        );
        if expected_count == 0 {
            continue;
        }
        if *lang == "objc" {
            assert!(
                rows.iter().any(|row| {
                    row.get("source")
                        .and_then(|v| v.get("rule_id"))
                        .and_then(|v| v.as_str())
                        == Some("objc.source.stdin_fgets")
                }),
                "objc: mega_flow must attribute at least one finding to the configured fgets output-argument source:\n{out}"
            );
        }
        if *lang == "lua" {
            assert!(
                rows.iter().all(|row| {
                    row.get("sink")
                        .and_then(|v| v.get("rule_id"))
                        .and_then(|v| v.as_str())
                        == Some("lua.cmdi.os_execute")
                }),
                "lua: generic Executor.execute must not be classified as LuaSQL SQL injection:\n{out}"
            );
        }
        for row in rows {
            let finding_id = row.get("finding_id").and_then(|v| v.as_str()).unwrap_or("");
            assert!(
                finding_id.starts_with("S:") && finding_id.len() == 18,
                "{lang}: finding missing stable S: id:\n{out}"
            );
            assert!(
                row.get("source")
                    .and_then(|v| v.get("rule_id"))
                    .and_then(|v| v.as_str())
                    .is_some_and(|id| !id.is_empty()),
                "{lang}: finding missing source rule id:\n{out}"
            );
            assert!(
                row.get("sink")
                    .and_then(|v| v.get("rule_id"))
                    .and_then(|v| v.as_str())
                    .is_some_and(|id| !id.is_empty()),
                "{lang}: finding missing sink rule id:\n{out}"
            );
        }
        if *lang == "python" {
            assert!(
                !rows.iter().any(|row| {
                    row.get("source")
                        .and_then(|source| source.get("rule_id"))
                        .and_then(|v| v.as_str())
                        == Some("entry-point.decorator_handler.param_0")
                        && row
                            .get("source")
                            .and_then(|source| source.get("enclosing_fn"))
                            .and_then(|v| v.as_str())
                            == Some("run_pipeline")
                }),
                "python: undecorated run_pipeline must not inherit handle_request decorators:\n{out}"
            );
        }
        assert!(
            rows.iter().any(|row| row
                .get("chain_display")
                .and_then(|v| v.as_array())
                .is_some_and(|c| c.len() >= 2)),
            "{lang}: expected at least one multi-hop mega_flow chain:\n{out}"
        );
        let expected_hops = expected_mega_chain_hops(lang);
        assert!(
            rows.iter().any(|row| {
                let chain = row
                    .get("chain_display")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>();
                expected_hops.iter().all(|hop| chain_contains_hop(&chain, hop))
            }),
            "{lang}: expected a canonical mega_flow chain containing {:?}:\n{out}",
            expected_hops
        );
    }
}

#[test]
fn taint_analysis_python_mega_alias_path_does_not_render_overapprox_edges() {
    let ws = mega_path("python");
    if !ws.exists() {
        return;
    }
    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--all",
    ])
    .unwrap();
    assert!(
        !out.contains("(over-approx)"),
        "alias-resolved concrete mega_flow path must not render over-approx edges:\n{out}"
    );
    assert!(
        out.contains("run_orchestrate(envelope)") && out.contains("run_pipeline -> orchestrate"),
        "expected alias call to render as the concrete orchestrate hop:\n{out}"
    );
}

#[test]
fn mega_flow_fixtures_cover_declared_language_constructs() {
    for lang in MEGA_FLOW_LANGS {
        let ws = mega_path(lang);
        if !ws.exists() {
            continue;
        }
        let text = read_fixture_text(&ws);
        assert!(
            text.contains("NEGATIVE"),
            "{lang}: mega_flow fixture must include at least one explicit negative clean-twin sink"
        );
        for marker in required_mega_construct_markers(lang) {
            assert!(
                text.contains(marker),
                "{lang}: mega_flow fixture is missing required construct marker `{marker}`"
            );
        }
    }
}

#[test]
fn mega_flow_exports_adapter_facts_for_taint_engine() {
    for lang in MEGA_FLOW_LANGS {
        let ws = mega_path(lang);
        if !ws.exists() {
            continue;
        }
        let out = run(&["export", ws.to_str().unwrap()]).unwrap();
        let export: serde_json::Value =
            serde_json::from_str(&out).unwrap_or_else(|e| panic!("{lang}: invalid export JSON: {e}\n{out}"));

        assert!(
            export_array_len(&export, &["files"]) > 0,
            "{lang}: export must include file facts"
        );
        assert!(
            export
                .get("files")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .flat_map(|file| file.get("decls").and_then(|v| v.as_array()).into_iter().flatten())
                .any(|decl| decl
                    .get("params")
                    .and_then(|v| v.as_array())
                    .is_some_and(|p| !p.is_empty())),
            "{lang}: export must include declaration parameter facts"
        );
        assert!(
            export
                .get("files")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .flat_map(|file| file
                    .get("imports")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten())
                .next()
                .is_some(),
            "{lang}: export must include import/include facts"
        );
        assert!(
            export
                .get("files")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .flat_map(|file| file.get("refs").and_then(|v| v.as_array()).into_iter().flatten())
                .any(|r| r.get("kind").and_then(|v| v.as_str()) == Some("call")),
            "{lang}: export must include call refs"
        );
        assert!(
            export
                .get("files")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .flat_map(|file| file
                    .get("strings")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten())
                .next()
                .is_some(),
            "{lang}: export must include string refs"
        );

        let mut event_kinds = BTreeSet::new();
        collect_flow_event_kinds(&export, &mut event_kinds);
        for kind in required_mega_flow_event_kinds(lang) {
            assert!(
                event_kinds.contains(*kind),
                "{lang}: export missing FlowEvent::{kind}; got {event_kinds:?}"
            );
        }

        assert!(
            export_array_len(&export, &["taint_graph", "call_edges"]) > 0,
            "{lang}: export taint_graph must include resolved call edges"
        );
        assert!(
            export_array_len(&export, &["taint_graph", "reachable_facts"]) > 0,
            "{lang}: export taint_graph must include reachable facts"
        );
        assert!(
            reachable_fact_kind_count(&export, "arg") > 0,
            "{lang}: reachable facts must include sink/source argument refs"
        );
        assert!(
            reachable_fact_kind_count(&export, "write") > 0,
            "{lang}: reachable facts must include assignment/write refs"
        );
        if mega_flow_requires_alias_map(lang) {
            assert!(
                alias_map_entry_count(&export) > 0,
                "{lang}: export taint_graph must include import/symbol alias facts"
            );
        }
        assert!(
            export_array_len(&export, &["taint_graph", "assign_chains"]) > 0,
            "{lang}: export taint_graph must include assignment-chain facts"
        );
        assert!(
            export_array_len(&export, &["taint_graph", "intra_taint"]) > 0,
            "{lang}: export taint_graph must include intraprocedural taint facts"
        );
        assert!(
            export_array_len(&export, &["taint_graph", "chains"]) > 0,
            "{lang}: export taint_graph must include source-to-sink chain facts"
        );
    }
}

#[test]
fn mega_flow_cli_surfaces_run_across_every_language() {
    for lang in MEGA_FLOW_LANGS {
        let ws = mega_path(lang);
        if !ws.exists() {
            continue;
        }
        let workspace = ws.to_str().unwrap();
        let entry = mega_entry_symbol(lang);
        let target = mega_target_symbol(lang);
        let rules = rules_dir();

        let commands: Vec<Vec<&str>> = vec![
            vec!["inspect", workspace, "--query", target, "--format", "json"],
            vec!["trace", workspace, entry, "--format", "json"],
            vec!["export", workspace],
            vec!["dump-hir", workspace, entry],
            vec!["dump-cfg", workspace, entry],
            vec!["dump-edges", workspace, "--limit", "5"],
            vec!["dump-resolve", workspace, target],
            vec!["dump-taint", workspace, "--source", entry, "--format", "json"],
            vec![
                "security",
                workspace,
                "--rules-dir",
                &rules,
                "source-analysis",
                "--format",
                "json",
                "--all",
            ],
        ];

        for args in commands {
            let out = run(&args).unwrap_or_default();
            assert!(
                !out.trim().is_empty(),
                "{lang}: command returned empty output: {args:?}"
            );
        }
    }
}

#[test]
fn typescript_named_import_execsync_enumerates_as_sink() {
    let ws = micro_path("typescript");
    if !ws.exists() {
        return;
    }
    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "sinks",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    assert!(
        out.contains("typescript.cmdi.exec_sync_imported"),
        "expected named-import execSync sink coverage in TS micro fixture:\n{out}"
    );
}

#[test]
fn javascript_and_typescript_mysql_db_query_enumerate_as_sql_sinks() {
    for (lang, rule_id) in &[
        ("javascript", "javascript.sqli.method_query_concat"),
        ("typescript", "typescript.sqli.method_query_concat"),
    ] {
        let ws = micro_path(lang);
        if !ws.exists() {
            continue;
        }
        let out = run(&[
            "security",
            ws.to_str().unwrap(),
            "--rules-dir",
            &rules_dir(),
            "sinks",
            "--tag",
            "sql-injection",
            "--format",
            "json",
            "--all",
        ])
        .unwrap();
        assert!(
            out.contains(rule_id),
            "{lang}: expected db.query SQL sink coverage in micro fixture:\n{out}"
        );
    }
}

#[test]
fn deps_inventory_runs() {
    let ws = micro_path("python");
    if !ws.exists() {
        return;
    }
    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "deps",
    ])
    .unwrap();
    // Expect the trailing summary line ("(N package(s))") which the
    // search-style renderer prints whether or not any deps matched.
    assert!(out.contains("package(s)"), "got:\n{out}");
}

#[test]
fn taint_analysis_json_paginates() {
    let ws = micro_path("python");
    if !ws.exists() {
        return;
    }
    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--format",
        "json",
        "--context",
        "16k",
    ])
    .unwrap();
    assert!(out.contains("\"page\""), "expected paged JSON envelope:\n{out}");
    assert!(out.contains("\"rows\""), "expected `rows` array:\n{out}");
}

#[test]
fn production_profile_excludes_common_language_and_build_layouts() {
    let ws = temp_workspace("production-profile");
    let vulnerable = r#"
import os
from flask import request

def handle():
    cmd = request.args.get("cmd")
    os.system(cmd)
"#;
    for relative in [
        "app.py",
        "tests/test_app.py",
        "testdata/go_fixture.py",
        "src/test/java/AppTest.py",
        ".venv/lib/python/site-packages/pkg.py",
        "coverage/report.py",
        "cypress/e2e/spec.py",
        "benches/bench_cmd.py",
        "CMakeFiles/generated_cmd.py",
        "docs/example_cmd.py",
        "support/release.py",
    ] {
        let path = ws.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create production-profile fixture dir");
        }
        std::fs::write(path, vulnerable).expect("write production-profile fixture");
    }

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--profile",
        "production",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("production profile JSON");
    let rows = parsed.as_array().expect("finding array");
    assert_eq!(rows.len(), 1, "only first-party app.py should remain:\n{out}");
    let row = &rows[0];
    assert!(
        row.to_string().contains("app.py"),
        "remaining production finding should come from app.py:\n{out}"
    );
    for excluded in [
        "tests/",
        "testdata/",
        "src/test/",
        ".venv/",
        "coverage/",
        "cypress/",
        "benches/",
        "CMakeFiles/",
        "docs/",
        "support/",
    ] {
        assert!(
            !out.contains(excluded),
            "production profile leaked excluded path `{excluded}`:\n{out}"
        );
    }
}

#[test]
fn production_profile_excludes_flows_through_test_lineage() {
    let ws = temp_workspace("production-profile-test-lineage");
    std::fs::write(
        ws.join("app.py"),
        r#"
from flask import request
from tests.helper import run

def handle():
    run(request.args.get("cmd"))
"#,
    )
    .expect("write app");
    std::fs::create_dir_all(ws.join("tests")).expect("create tests dir");
    std::fs::write(ws.join("tests/__init__.py"), "").expect("write package marker");
    std::fs::write(
        ws.join("tests/helper.py"),
        r#"
from sink import exec_cmd

def run(cmd):
    exec_cmd(cmd)
"#,
    )
    .expect("write test helper");
    std::fs::write(
        ws.join("sink.py"),
        r#"
import os

def exec_cmd(cmd):
    os.system(cmd)
"#,
    )
    .expect("write sink");

    let broad = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    assert!(
        broad.contains("\"finding_id\"") && broad.contains("tests/helper.py"),
        "broad scan should prove the test-lineage flow before production filtering:\n{broad}"
    );

    let production = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--profile",
        "production",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&production).expect("production profile JSON");
    assert_eq!(
        parsed.as_array().map(Vec::len),
        Some(0),
        "production profile must drop flows whose proof path crosses tests:\n{production}"
    );
}

#[test]
fn rulepack_rules_surface_common_sink_shapes() {
    let ws = temp_workspace("rulepack-common-sink-shapes");
    std::fs::write(
        ws.join("interp_prepare.pl"),
        r#"
use DBI;
sub lookup_user {
    my ($dbh, $name) = @_;
    return $dbh->prepare("SELECT id FROM users WHERE name = '$name'");
}

sub eval_expr {
    my ($expr) = @_;
    return eval $expr;
}
"#,
    )
    .expect("write Perl fixture");
    std::fs::write(
        ws.join("uaf.cpp"),
        r#"
#include <cstdio>
struct Cache { int x; };
void use_after_free(Cache *cache) {
    delete cache;
    if (cache->x > 0) {
        std::printf("%d\n", cache->x);
    }
}
"#,
    )
    .expect("write C++ fixture");
    std::fs::write(
        ws.join("sql.lua"),
        r#"
local _luasql = require("luasql")
function lookup(conn, name)
    conn:execute("SELECT id FROM users WHERE name = '" .. name .. "'")
end
"#,
    )
    .expect("write Lua fixture");
    std::fs::write(
        ws.join("Cases.m"),
        r#"
#import <Foundation/Foundation.h>
void run(NSString *host) {
    NSTask *task = [NSTask new];
    task.launchPath = @"/bin/sh";
    task.arguments = @[@"-c", [@"ping -c 1 " stringByAppendingString:host]];
}
void render(WKWebView *wv, NSString *body) {
    NSString *html = [@"<p>" stringByAppendingString:body];
    [wv loadHTMLString:html baseURL:nil];
}
id evalExpression(NSString *expr) {
    return [NSExpression expressionWithFormat:expr];
}
"#,
    )
    .expect("write ObjC fixture");
    std::fs::write(
        ws.join("cmd.rb"),
        r#"
def ping(host)
  `ping -c 1 #{host}`
end
"#,
    )
    .expect("write Ruby fixture");
    std::fs::write(
        ws.join("race.rs"),
        r#"
use std::sync::Mutex;
fn withdraw(balance: &Mutex<i32>, amount: i32) {
    let available = *balance.lock().unwrap();
    if available >= amount {
        *balance.lock().unwrap() -= amount;
    }
}
"#,
    )
    .expect("write Rust fixture");
    std::fs::write(
        ws.join("Comment.scala"),
        r#"
object Comment {
  def comment(body: String): String = "<div>" + body + "</div>"
}
"#,
    )
    .expect("write Scala fixture");
    std::fs::write(
        ws.join("xss.erl"),
        r#"
-include_lib("cowboy/include/cowboy.hrl").
-module(xss).
-export([handle/2]).
handle(Req, State) ->
    Q = cowboy_req:binding(q, Req),
    cowboy_req:reply(200, #{}, <<"<p>", Q/binary, "</p>">>, Req),
    {ok, Req, State}.
"#,
    )
    .expect("write Erlang fixture");
    std::fs::write(
        ws.join("Servlet.kt"),
        r#"
class Handler {
    fun handle(resp: javax.servlet.http.HttpServletResponse, name: String) {
        resp.writer.write("<p>" + name + "</p>")
    }
}
"#,
    )
    .expect("write Kotlin fixture");
    std::fs::write(
        ws.join("xss.php"),
        r#"
<?php
$q = $_GET['q'];
echo "<p>$q</p>";
?>
"#,
    )
    .expect("write PHP fixture");
    std::fs::write(
        ws.join("pollute.ts"),
        r#"
function merge(target: any, source: any) {
    for (const key in source) {
        if (typeof source[key] === "object") {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}
"#,
    )
    .expect("write TypeScript fixture");
    std::fs::write(
        ws.join("show.html.erb"),
        r#"
<div>
  <%= raw @comment %>
</div>
"#,
    )
    .expect("write ERB fixture");
    std::fs::write(ws.join("Gemfile"), "gem \"actionview\"\n").expect("write Ruby dependency fixture");

    let mut checked = 0usize;
    for rule in [
        "cpp.memory.delete_use_after",
        "lua.sqli.luasql_execute",
        "objc.cmdi.nstask_setters",
        "objc.xss.wkwebview_loadhtml_concat",
        "objc.eval.nsexpression_format",
        "perl.sqli.dbi_prepare_interp",
        "perl.eval.builtin_eval",
        "ruby.cmdi.kernel_backtick",
        "scala.xss.html_string_concat",
        "erlang.xss.cowboy_binary_concat",
        "kotlin.xss.servletresponse_writer_write",
        "php.xss.echo",
        "typescript.proto_pollution.recursive_merge",
        "ruby.xss.raw",
    ] {
        if !rule_is_enabled(rule) {
            continue;
        }
        checked += 1;
        let out = run(&[
            "security",
            ws.to_str().unwrap(),
            "--rules-dir",
            &rules_dir(),
            "sinks",
            "--rule",
            rule,
            "--format",
            "json",
            "--all",
        ])
        .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&out).unwrap_or_else(|e| panic!("{rule}: invalid JSON: {e}\n{out}"));
        let rows = parsed
            .as_array()
            .or_else(|| parsed["rows"].as_array())
            .expect("sink rows");
        assert!(
            !rows.is_empty(),
            "{rule} should match its benchmark gap fixture:\n{out}"
        );
    }
    assert!(checked > 0, "common sink shape test skipped every rule");
}

#[test]
fn inferred_sources_use_objc_bound_parameter_name() {
    let ws = temp_workspace("objc-inferred-param");
    std::fs::write(
        ws.join("Expr.m"),
        r#"
#import <Foundation/Foundation.h>
@interface E: NSObject
+ (id)evalExpression:(NSString *)expr;
@end
@implementation E
+ (id)evalExpression:(NSString *)expr {
    return [NSExpression expressionWithFormat:expr];
}
@end
"#,
    )
    .expect("write ObjC fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "source-analysis",
        "--inferred-sources",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("invalid JSON: {e}\n{out}"));
    assert!(
        rows.iter()
            .any(|row| row["source"]["text"] == "expr" && row["source"]["enclosing_fn"] == "evalExpression"),
        "ObjC inferred source should seed the bound parameter name, not its type:\n{out}"
    );
    assert!(
        rows.iter().all(|row| row["source"]["text"] != "NSString"),
        "ObjC inferred source leaked type name as parameter:\n{out}"
    );
}

#[test]
fn taint_flows_connect_visible_sources_to_sinks() {
    let ws = temp_workspace("visible-source-to-sink-flows");
    std::fs::create_dir_all(ws.join("ruby/app/controllers")).expect("ruby controllers dir");
    std::fs::create_dir_all(ws.join("ruby/app/views/comments")).expect("ruby views dir");
    std::fs::create_dir_all(ws.join("ts")).expect("ts dir");
    std::fs::create_dir_all(ws.join("go")).expect("go dir");
    std::fs::create_dir_all(ws.join("java")).expect("java dir");
    std::fs::create_dir_all(ws.join("js")).expect("js dir");
    std::fs::create_dir_all(ws.join("sol")).expect("sol dir");

    std::fs::write(
        ws.join("c_shell.c"),
        r#"
#include <stdlib.h>
void run_cmd(const char *user) {
    char buf[256];
    sprintf(buf, "echo %s", user);
    system(buf);
}
"#,
    )
    .expect("c fixture");
    std::fs::write(
        ws.join("lua_cases.lua"),
        r#"
local _luasql = require("luasql")
function handle()
  local args = ngx.req.get_uri_args()
  local q = args.q
  ngx.print("<p>" .. q .. "</p>")
end
local M = {}
function M.find(conn, name)
  conn:execute("SELECT id FROM users WHERE name = '" .. name .. "'")
end
"#,
    )
    .expect("lua fixture");
    std::fs::write(
        ws.join("dart_xss.dart"),
        r#"
void render(String comment, dynamic div) {
  final html = '<p>' + comment + '</p>';
  div.innerHtml = html;
}
"#,
    )
    .expect("dart fixture");
    std::fs::write(
        ws.join("elixir_xss.ex"),
        r#"
alias Phoenix_html
defmodule Page do
  def show(conn) do
    body = conn.params["body"]
    Phoenix.HTML.raw("<p>" <> body <> "</p>")
  end
end
"#,
    )
    .expect("elixir fixture");
    std::fs::write(
        ws.join("erlang_xss.erl"),
        r##"
-include_lib("cowboy/include/cowboy.hrl").
-module(erlang_xss).
-export([handle/2]).
handle(Req, State) ->
  Q = cowboy_req:binding(q, Req),
  cowboy_req:reply(200, #{}, <<"<p>", Q/binary, "</p>">>, Req),
  {ok, Req, State}.
"##,
    )
    .expect("erlang fixture");
    std::fs::write(
        ws.join("go/main.go"),
        r#"
package main
import (
  "net/http"
  "path/filepath"
)
func handler(w http.ResponseWriter, r *http.Request) {
  name := r.URL.Query().Get("name")
  Read(name)
}
func Read(name string) string {
  return filepath.Join("/data", name)
}
"#,
    )
    .expect("go fixture");
    std::fs::write(
        ws.join("java/Users.java"),
        r#"
class Users {
  static void handle(String name, java.sql.Connection conn) throws Exception {
    findByName(conn, name);
  }
  static void findByName(java.sql.Connection conn, String name) throws Exception {
    java.sql.Statement st = conn.createStatement();
    st.executeQuery("SELECT * FROM users WHERE name='" + name + "'");
  }
}
"#,
    )
    .expect("java fixture");
    std::fs::write(
        ws.join("ruby/app/controllers/comments_controller.rb"),
        r#"
class CommentsController
  def show
    @comment = params[:body].to_s
  end
end
"#,
    )
    .expect("ruby controller fixture");
    std::fs::write(
        ws.join("ruby/app/views/comments/show.html.erb"),
        "<%= raw @comment %>\n",
    )
    .expect("ruby erb fixture");
    std::fs::write(
        ws.join("ts/server.ts"),
        r#"
import { merge } from './util';
function handler(req: any) {
  const body = req.body;
  const target: any = {};
  merge(target, body);
}
"#,
    )
    .expect("ts server fixture");
    std::fs::write(
        ws.join("ts/util.ts"),
        r#"
export function merge(target: any, source: any) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}
"#,
    )
    .expect("ts util fixture");
    std::fs::write(
        ws.join("js/index.js"),
        r##"
function createHtmlDocument(html) { return html }
function handler(req, res) {
  const loc = req.query.loc
  const html = createHtmlDocument('profile', '<a href="' + loc + '">x</a>')
  res.send(html)
}
"##,
    )
    .expect("js fixture");
    std::fs::write(
        ws.join("sol/A.sol"),
        r#"
contract A {
  function f(address t) public {
    assembly { let ok := call(gas(), t, 0, 0, 0, 0, 0) }
  }
}
"#,
    )
    .expect("solidity fixture");

    let out = run(&[
        "security",
        ws.to_str().unwrap(),
        "--rules-dir",
        &rules_dir(),
        "taint-analysis",
        "--inferred-sources",
        "--format",
        "json",
        "--all",
    ])
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("taint JSON");
    let mut rule_ids = BTreeSet::new();
    collect_rule_ids(&parsed, &mut rule_ids);
    for expected in [
        "c.cmdi.system",
        "lua.sqli.luasql_execute",
        "dart.xss.innerhtml",
        "elixir.xss.phoenix_html_raw",
        "erlang.xss.cowboy_binary_concat",
        "go.path.filepath_join",
        "java.sqli.statement_executequery",
        "typescript.proto_pollution.recursive_merge",
        "javascript.xss.create_html_document_href_concat",
        "solidity.eval.inline_assembly_call",
    ] {
        if !rule_is_enabled(expected) {
            continue;
        }
        assert!(
            rule_ids.contains(expected),
            "expected taint finding carrying {expected}; got rules {rule_ids:?}\n{out}"
        );
    }
}

#[test]
fn pack_tree_uses_actual_yaml_file_names() {
    let rules = rules_dir();
    let out = run(&[
        "security",
        &rules,
        "--rules-dir",
        &rules,
        "pack",
        "--tree",
        "--lang",
        "python",
        "--all",
    ])
    .unwrap();
    assert!(
        out.contains("    remote.yml"),
        "expected actual source file in tree:\n{out}"
    );
    assert!(
        out.contains("    all.yml"),
        "expected actual sanitizer file in tree:\n{out}"
    );
    assert!(
        !out.contains("    flask.yml"),
        "tree should not invent filenames from rule ids:\n{out}"
    );
    assert!(
        !out.contains("    sanitizer.yml"),
        "tree should use the actual sanitizer filename on disk:\n{out}"
    );
}

#[test]
fn pack_audit_marks_solidity_as_ecosystem_specific() {
    let rules = rules_dir();
    let out = run(&[
        "security",
        &rules,
        "--rules-dir",
        &rules,
        "pack",
        "--audit",
        "--lang",
        "solidity",
        "--format",
        "json",
    ])
    .unwrap();
    assert!(out.contains("\"language\": \"solidity\""), "got:\n{out}");
    assert!(
        out.contains("\"canonical_sink_families_applicable\": false"),
        "solidity should be marked outside the canonical web-family audit:\n{out}"
    );
}

#[test]
fn pack_audit_has_no_unexplained_canonical_family_gaps() {
    let rules = rules_dir();
    let out = run(&[
        "security",
        &rules,
        "--rules-dir",
        &rules,
        "pack",
        "--audit",
        "--format",
        "json",
    ])
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("pack audit JSON");
    let languages = parsed
        .get("languages")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("missing languages array:\n{out}"));
    let mut gaps = Vec::new();
    for lang in languages {
        if lang
            .get("canonical_sink_families_applicable")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
        {
            continue;
        }
        let language = lang
            .get("language")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<unknown>");
        let sinks = lang
            .get("sinks")
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("{language}: missing sinks object:\n{out}"));
        for (family, entry) in sinks {
            let not_applicable = entry
                .get("not_applicable")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let enabled = entry
                .get("enabled")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if !not_applicable && enabled == 0 {
                gaps.push(format!("{language}/{family}"));
            }
        }
    }
    assert!(
        gaps.is_empty(),
        "pack audit has unexplained canonical family gaps: {}\n{out}",
        gaps.join(", ")
    );
}
