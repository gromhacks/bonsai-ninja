#!/usr/bin/env python3
"""Exhaustive release-binary CLI/switch validation.

The matrix intentionally runs every command family and every public switch at
least once per language. Destructive cache commands run only against temporary
copies of the fixture workspaces. By default the script also runs the Redis
realworld header/footer stress sweep; pass --skip-realworld for a faster
language-fixture-only pass.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LANGS = [
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
]

EXPECTED_FINDINGS = {
    # Release-binary source-to-sink finding counts under
    # `taint-analysis --inferred-sources --all`. These match the
    # canonical `security_pipeline_regressions::mega_flow` baselines
    # (`expected_mega_flow_findings_with_inferred_sources`). Refreshed
    # 2026-05-29: the FN-language construct gaps closed (cpp/csharp/
    # dart/elixir/java/scala 0→1, php 0→2); swift settled at 1 after
    # the redundant inferred-source over-claim was filtered; go 2→1
    # and objc 2→1 after redundant-inferred / xxe-over-claim removal;
    # python 5→3 and dart→1 after the combiner's group_id+sink-site
    # dedup collapsed duplicate entry-chain rows; python 3→2 after
    # local inferred callable-object paths grouped into one combined
    # row while the concrete Flask source row stayed intact; python
    # 2→1 once the concrete Flask source and equivalent inferred entry
    # chain became member ids on one grouped row; erlang 2→1 and
    # solidity 3→2 after equivalent inferred/member paths are grouped
    # into one real report row.
    "c": 1,
    "cpp": 1,
    "csharp": 1,
    "dart": 1,
    "elixir": 1,
    "erlang": 1,
    "go": 1,
    "java": 1,
    "javascript": 1,
    "kotlin": 1,
    # Lua previously reported two extra SQLi findings from generic
    # Executor.execute calls. LuaSQL sinks now require LuaSQL package
    # evidence, leaving the one real os.execute command-injection flow.
    "lua": 1,
    "objc": 1,
    "perl": 2,
    "php": 2,
    "python": 1,
    # Equivalent receiver-derived evidence is grouped into the one distinct
    # stdin_gets -> Kernel.system vulnerability.
    "ruby": 1,
    "rust": 1,
    "scala": 1,
    "solidity": 2,
    "swift": 1,
    "typescript": 1,
}

MatrixEntry = tuple[str, list[Any], tuple[int, ...], bool, bool]

CONTEXT_FOOTER_RE = re.compile(r"context\s+~?([0-9,]+) / ([0-9,]+) tokens \((\d+)%\)")
PAGE_FOOTER_RE = re.compile(
    r"^page\s+\d+\s+of\s+[0-9,]+\s+\([0-9,]+\s+rows\)", re.MULTILINE
)
TOTAL_FOOTER_RE = re.compile(r"^total\s+[0-9,]+\s+\S+", re.MULTILINE)


class Failure:
    def __init__(
        self,
        lang: str,
        label: str,
        args: list[str],
        message: str,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        self.lang = lang
        self.label = label
        self.args = args
        self.message = message
        self.stdout = stdout
        self.stderr = stderr


@dataclass
class DerivedValidation:
    entry: str
    target: str
    source_rule: str
    sink_rule: str
    source_file: str
    sink_file: str
    call_filter_query: str
    call_filter_file: str
    call_filter_fn: str
    first_file: str
    flow_id: str | None
    group_id: str | None
    edge_id: str | None
    node_id: str | None
    candidate_id: str | None
    taint_id: str | None


def is_inferred_finding(row: dict[str, Any]) -> bool:
    return (child_mapping(row, "source").get("rule_id") or "").startswith(
        "entry-point."
    )


def is_module_synthetic(name: object) -> bool:
    return isinstance(name, str) and name.startswith("__module__")


def good_primary_finding(row: dict[str, Any]) -> bool:
    if is_inferred_finding(row):
        return False
    chain = row.get("chain_display") or []
    head = (
        chain[0]
        if isinstance(chain, list) and chain
        else (child_mapping(row, "source").get("enclosing_fn") or "")
    )
    sink_enclosing = child_mapping(row, "sink").get("enclosing_fn") or ""
    return not is_module_synthetic(head) and not is_module_synthetic(sink_enclosing)


def select_primary_finding(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return next(
        (row for row in rows if good_primary_finding(row)),
        next(
            (row for row in rows if not is_inferred_finding(row)),
            rows[0],
        ),
    )


def function_names_from_export(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    names = [
        function.get("name")
        for function in value.get("taint_graph", {}).get("functions", []) or []
        if isinstance(function, dict) and isinstance(function.get("name"), str)
    ]
    names.extend(
        function.get("name")
        for function in value.get("functions", []) or []
        if isinstance(function, dict) and isinstance(function.get("name"), str)
    )
    names.extend(
        function.get("function")
        for function in value.get("flow_graph", []) or []
        if isinstance(function, dict) and isinstance(function.get("function"), str)
    )
    return names


def preferred_function(names: list[str], candidates: set[str]) -> str | None:
    return next((name for name in names if name in candidates), None)


def finding_symbols(first: dict[str, Any]) -> tuple[str | None, str | None]:
    chain = [name for name in first.get("chain_display") or [] if isinstance(name, str)]
    source_enclosing = child_mapping(first, "source").get("enclosing_fn")
    entry = chain[0] if chain else source_enclosing
    if not isinstance(entry, str):
        entry = None

    sink_enclosing = child_mapping(first, "sink").get("enclosing_fn")
    if is_module_synthetic(sink_enclosing) and chain:
        target = next(
            (name for name in reversed(chain) if not is_module_synthetic(name)),
            None,
        )
    else:
        target = sink_enclosing or (chain[-1] if chain else entry)
    return entry, target if isinstance(target, str) else None


def finding_call_filter(
    first: dict[str, Any],
    target: str,
    sink_text: str,
    sink_file: str,
) -> tuple[str, str, str]:
    taint_path = first.get("taint_path")
    if not isinstance(taint_path, list):
        return sink_text, sink_file, target
    for step in reversed(taint_path):
        if not isinstance(step, dict):
            continue
        callee = step.get("callee")
        caller = step.get("caller")
        call_file = step.get("file")
        if callee == target and isinstance(caller, str) and isinstance(call_file, str):
            return callee, Path(call_file).name, caller
    return sink_text, sink_file, target


def first_collection_field(value: Any, collection: str, field: str) -> Any:
    if not isinstance(value, dict):
        return None
    rows = value.get(collection)
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return None
    return rows[0].get(field)


def first_list_field(value: Any, field: str) -> Any:
    if not isinstance(value, list) or not value or not isinstance(value[0], dict):
        return None
    return value[0].get(field)


def child_mapping(value: dict[str, Any], field: str) -> dict[str, Any]:
    child = value.get(field)
    return child if isinstance(child, dict) else {}


def basename_or_default(value: Any, default: str) -> str:
    return Path(value).name if isinstance(value, str) and value else default


def append_optional_entry(
    matrix: list[MatrixEntry],
    identifier: str | None,
    label: str,
    args: list[Any],
    *,
    ok: tuple[int, ...] = (0,),
    nonempty: bool = False,
    json_out: bool = False,
) -> None:
    if identifier:
        matrix.append((label, args, ok, nonempty, json_out))


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def find_bin(root: Path, explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).resolve()
    for candidate in [
        root / "target" / "release" / "bonsai-ninja",
        root / "target" / "debug" / "bonsai-ninja",
    ]:
        if candidate.exists():
            return candidate
    raise SystemExit("missing bonsai-ninja binary; run `cargo build --release`")


def json_load(stdout: str) -> Any:
    return json.loads(stdout or "null")


def first_node_id(value: Any) -> str | None:
    if isinstance(value, dict):
        node_id = value.get("node_id")
        if isinstance(node_id, str):
            return node_id
        for child in value.values():
            found = first_node_id(child)
            if found:
                return found
    if isinstance(value, list):
        for child in value:
            found = first_node_id(child)
            if found:
                return found
    return None


def collect_flow_ids(value: Any) -> tuple[list[str], list[str]]:
    flows: list[str] = []
    groups: list[str] = []
    if not isinstance(value, dict):
        return flows, groups
    for section in ("decl_hits", "hits"):
        for hit in value.get(section, []) or []:
            for flow in hit.get("flows", []) or []:
                flow_id = flow.get("flow_id")
                if isinstance(flow_id, str):
                    flows.append(flow_id)
            for group in hit.get("groups", []) or []:
                group_id = group.get("group_id")
                if isinstance(group_id, str):
                    groups.append(group_id)
    return flows, groups


def export_files(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    return [
        file.get("path", "")
        for file in value.get("files", []) or []
        if isinstance(file, dict)
    ]


class Validator:
    def __init__(self, root: Path, binary: Path, rules_dir: Path) -> None:
        self.root = root
        self.binary = binary
        self.rules_dir = rules_dir
        self.failures: list[Failure] = []
        self.counts: list[tuple[str, int]] = []

    def run(self, args: list[Any]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.binary), *[str(arg) for arg in args]],
            cwd=self.root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def check(
        self,
        lang: str,
        label: str,
        args: list[Any],
        *,
        ok: tuple[int, ...] = (0,),
        nonempty: bool = False,
        json_out: bool = False,
    ) -> Any:
        str_args = [str(arg) for arg in args]
        proc = self.run(str_args)
        if proc.returncode not in ok:
            self.failures.append(
                Failure(
                    lang,
                    label,
                    str_args,
                    f"exit {proc.returncode}",
                    proc.stdout[:900],
                    proc.stderr[:900],
                )
            )
            return None
        if nonempty and not (proc.stdout + proc.stderr).strip():
            self.failures.append(Failure(lang, label, str_args, "empty output"))
        if not json_out:
            self.validate_text_footer(lang, label, str_args, proc.stdout)
        if json_out:
            try:
                return json_load(proc.stdout)
            except Exception as exc:  # noqa: BLE001 - report parser context.
                self.failures.append(
                    Failure(
                        lang,
                        label,
                        str_args,
                        f"json parse {exc}",
                        proc.stdout[:900],
                        proc.stderr[:900],
                    )
                )
                return None
        return proc.stdout

    def validate_text_footer(
        self, lang: str, label: str, args: list[str], stdout: str
    ) -> None:
        lines = [line for line in stdout.splitlines() if line.strip()]
        if not lines:
            return
        if lines[0].startswith(("page ", "context ", "next ")):
            self.failures.append(
                Failure(
                    lang,
                    label,
                    args,
                    f"footer appeared before command output: {lines[0]}",
                )
            )
        match = CONTEXT_FOOTER_RE.search(stdout)
        if match:
            used = int(match.group(1).replace(",", ""))
            budget = int(match.group(2).replace(",", ""))
            if used > budget and "single row cost exceeded --context" not in stdout:
                self.failures.append(
                    Failure(
                        lang,
                        label,
                        args,
                        f"context footer exceeded budget without oversized-row warning: {used}>{budget}",
                        stdout[-900:],
                    )
                )
        page_lines = [line for line in lines if PAGE_FOOTER_RE.match(line)]
        if page_lines and "next     " not in stdout and "end of results" not in stdout:
            self.failures.append(
                Failure(
                    lang,
                    label,
                    args,
                    "page footer missing next cursor or end-of-results marker",
                    stdout[-900:],
                )
            )
        if page_lines and not TOTAL_FOOTER_RE.search(stdout):
            self.failures.append(
                Failure(
                    lang,
                    label,
                    args,
                    "page footer missing total count line",
                    stdout[-900:],
                )
            )

    def validate_global(self) -> None:
        self.check("global", "help", ["--help"], nonempty=True)
        self.check("global", "version", ["--version"], nonempty=True)
        self.check("global", "short version", ["-V"], nonempty=True)
        self.check(
            "global", "theme help", ["--theme", "dracula", "--help"], nonempty=True
        )

    def derive_taint_rows(self, lang: str, ws: Path) -> list[dict[str, Any]] | None:
        expected_findings = EXPECTED_FINDINGS.get(lang, 1)
        taint = self.check(
            lang,
            "derive taint",
            [
                "security",
                ws,
                "taint-analysis",
                "--rules-dir",
                self.rules_dir,
                # The fixture expectations exercise the explicitly enabled
                # inferred-source surface.
                "--inferred-sources",
                "--format",
                "json",
                "--all",
            ],
            json_out=True,
        )
        raw_rows = taint.get("rows", []) if isinstance(taint, dict) else taint
        if (
            not isinstance(raw_rows, list)
            or len(raw_rows) != expected_findings
            or not all(isinstance(row, dict) for row in raw_rows)
        ):
            got = len(raw_rows) if isinstance(raw_rows, list) else "?"
            self.failures.append(
                Failure(
                    lang,
                    "derive taint",
                    ["security", str(ws), "taint-analysis"],
                    f"expected {expected_findings} findings, got {got}",
                )
            )
            return None

        rows: list[dict[str, Any]] = raw_rows
        if lang == "python" and any(
            child_mapping(row, "source").get("rule_id")
            == "entry-point.decorator_handler.param_0"
            and child_mapping(row, "source").get("enclosing_fn") == "run_pipeline"
            for row in rows
        ):
            self.failures.append(
                Failure(
                    lang,
                    "derive taint",
                    ["security", str(ws), "taint-analysis"],
                    "undecorated run_pipeline inherited handle_request decorators",
                )
            )
            return None
        return rows

    def derive_artifact_ids(
        self,
        lang: str,
        ws: Path,
        first: dict[str, Any],
        entry: str,
        target: str,
    ) -> tuple[str | None, str | None, str | None, str | None, str | None, str | None]:
        inspect = self.check(
            lang,
            "inspect derive",
            ["inspect", ws, "--query", target, "--format", "json", "--all"],
            ok=(0, 1),
            json_out=True,
        )
        flow_ids, group_ids = collect_flow_ids(inspect)
        flow_id = flow_ids[0] if flow_ids else first.get("representative_flow_id")
        group_id = group_ids[0] if group_ids else first.get("group_id")

        edges = self.check(
            lang,
            "edges derive",
            ["dump-edges", ws, "--format", "json", "--all"],
            json_out=True,
        )
        edge_id = first_list_field(edges, "edge_id")

        ast = self.check(
            lang,
            "ast derive",
            ["dump-ast", ws, "--function", entry, "--format", "json", "--all"],
            json_out=True,
        )
        node_id = first_node_id(ast)

        resolve = self.check(
            lang,
            "resolve derive",
            ["dump-resolve", ws, target, "--format", "json"],
            ok=(0, 2),
            json_out=True,
        )
        candidate_id = first_collection_field(resolve, "candidates", "candidate_id")

        dump_taint = self.check(
            lang,
            "dump-taint derive",
            ["dump-taint", ws, "--source", entry, "--format", "json"],
            json_out=True,
        )
        taint_id = first_collection_field(dump_taint, "records", "taint_id")
        return flow_id, group_id, edge_id, node_id, candidate_id, taint_id

    def derive_validation(
        self, lang: str, ws: Path, rows: list[dict[str, Any]]
    ) -> DerivedValidation | None:
        first = select_primary_finding(rows)
        entry, target = finding_symbols(first)
        source = child_mapping(first, "source")
        sink = child_mapping(first, "sink")

        export = self.check(lang, "export derive", ["export", ws], json_out=True)
        files = export_files(export)
        source_file = basename_or_default(source.get("file"), "app")
        first_file = Path(files[0]).name if files else source_file
        if not entry or not target:
            names = function_names_from_export(export)
            entry = entry or preferred_function(
                names, {"handle_request", "handleRequest", "handle", "Handle", "main"}
            )
            target = target or preferred_function(
                names,
                {
                    "execute",
                    "Execute",
                    "executeCmd",
                    "run",
                    "Run",
                    "persist",
                    "Persist",
                },
            )
            target = target or entry
        if not entry or not target:
            self.failures.append(
                Failure(lang, "derive symbols", [str(ws)], "missing entry/target")
            )
            return None

        sink_text = sink.get("text")
        sink_text = sink_text if isinstance(sink_text, str) and sink_text else target
        sink_file = basename_or_default(sink.get("file"), first_file)
        call_filter_query, call_filter_file, call_filter_fn = finding_call_filter(
            first, target, sink_text, sink_file
        )
        ids = self.derive_artifact_ids(lang, ws, first, entry, target)
        return DerivedValidation(
            entry=entry,
            target=target,
            source_rule=source.get("rule_id") or ".",
            sink_rule=sink.get("rule_id") or ".",
            source_file=source_file,
            sink_file=sink_file,
            call_filter_query=call_filter_query,
            call_filter_file=call_filter_file,
            call_filter_fn=call_filter_fn,
            first_file=first_file,
            flow_id=ids[0],
            group_id=ids[1],
            edge_id=ids[2],
            node_id=ids[3],
            candidate_id=ids[4],
            taint_id=ids[5],
        )

    def validate_lang(self, lang: str) -> None:
        ws = self.root / "examples" / lang / "mega_flow"
        if not ws.exists():
            self.failures.append(
                Failure(lang, "workspace", [str(ws)], "missing mega_flow")
            )
            return

        rows = self.derive_taint_rows(lang, ws)
        if rows is None:
            return
        context = self.derive_validation(lang, ws, rows)
        if context is None:
            return

        entry = context.entry
        target = context.target
        source_rule = context.source_rule
        sink_rule = context.sink_rule
        source_file = context.source_file
        sink_file = context.sink_file
        call_filter_query = context.call_filter_query
        call_filter_file = context.call_filter_file
        call_filter_fn = context.call_filter_fn
        first_file = context.first_file
        flow_id = context.flow_id
        group_id = context.group_id
        edge_id = context.edge_id
        node_id = context.node_id
        candidate_id = context.candidate_id
        taint_id = context.taint_id

        matrix: list[MatrixEntry] = []

        def add(
            label: str,
            args: list[Any],
            *,
            ok: tuple[int, ...] = (0,),
            nonempty: bool = False,
            json_out: bool = False,
        ) -> None:
            matrix.append((label, args, ok, nonempty, json_out))

        add(
            "global --no-color",
            ["--no-color", "defs", ws, "--limit", "1"],
            nonempty=True,
        )
        add(
            "global --no-cache",
            [
                "--no-cache",
                "inspect",
                ws,
                "--query",
                target,
                "--format",
                "json",
                "--all",
            ],
            ok=(0, 1),
            json_out=True,
        )
        add(
            "global --no-progress",
            [
                "--no-progress",
                "security",
                ws,
                "taint-analysis",
                "--rules-dir",
                self.rules_dir,
                "--format",
                "json",
                "--all",
            ],
            json_out=True,
        )
        add(
            "global --theme",
            ["--theme", "retro-amber", "calls", ws, "--limit", "1"],
            nonempty=True,
        )
        add("index", ["index", ws], nonempty=True)
        add("export", ["export", ws], json_out=True)
        add(
            "export --full-propagations",
            ["export", ws, "--full-propagations"],
            json_out=True,
        )
        add(
            "trace positional json",
            ["trace", ws, entry, "--format", "json"],
            json_out=True,
        )
        add(
            "trace --function",
            ["trace", ws, "--function", entry, "--format", "json"],
            json_out=True,
        )
        add(
            "trace --from --to",
            ["trace", ws, "--from", entry, "--to", target, "--format", "json"],
            json_out=True,
        )
        add("trace --context", ["trace", ws, entry, "--context", "4k"], nonempty=True)
        add("trace --page", ["trace", ws, entry, "--page", "1"], nonempty=True)
        add("trace --all", ["trace", ws, entry, "--all"], nonempty=True)
        add("trace text", ["trace", ws, entry, "--format", "text"], nonempty=True)
        add("trace dot", ["trace", ws, entry, "--format", "dot"], nonempty=True)
        add("diagnostics", ["diagnostics", ws])
        add("dump-hir positional", ["dump-hir", ws, entry], nonempty=True)
        add("dump-hir --symbol", ["dump-hir", ws, "--symbol", entry], nonempty=True)
        add("dump-cfg positional", ["dump-cfg", ws, entry], nonempty=True)
        add("dump-cfg --symbol", ["dump-cfg", ws, "--symbol", entry], nonempty=True)
        add(
            "dump-callgraph json",
            ["dump-callgraph", ws, "--format", "json", "--all"],
            json_out=True,
        )
        add(
            "dump-callgraph switches",
            [
                "dump-callgraph",
                ws,
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--format",
                "text",
            ],
            nonempty=True,
        )
        add(
            "dump-edges json",
            ["dump-edges", ws, "--format", "json", "--all"],
            json_out=True,
        )
        add(
            "dump-edges switches",
            [
                "dump-edges",
                ws,
                "--from",
                entry,
                "--to",
                target,
                "--precision",
                "exact",
                "--compact",
                "--limit",
                "10",
                "--context",
                "4k",
                "--page",
                "1",
                "--format",
                "text",
            ],
            nonempty=True,
        )
        append_optional_entry(
            matrix,
            edge_id,
            "dump-edges --edge",
            ["dump-edges", ws, "--edge", edge_id, "--format", "json"],
            json_out=True,
        )
        add(
            "dump-ast positional",
            ["dump-ast", ws, entry, "--format", "json", "--all"],
            json_out=True,
        )
        add(
            "dump-ast file switches",
            [
                "dump-ast",
                ws,
                "--file",
                first_file,
                "--compact",
                "--max-depth",
                "3",
                "--limit",
                "2",
                "--context",
                "4k",
                "--page",
                "1",
                "--format",
                "text",
            ],
            nonempty=True,
        )
        add(
            "dump-ast --function",
            ["dump-ast", ws, "--function", entry, "--format", "json"],
            json_out=True,
        )
        append_optional_entry(
            matrix,
            node_id,
            "dump-ast --node",
            ["dump-ast", ws, "--node", node_id, "--format", "json"],
            json_out=True,
        )
        add(
            "dump-resolve positional",
            ["dump-resolve", ws, target, "--format", "json"],
            ok=(0, 2),
            json_out=True,
        )
        add(
            "dump-resolve switches",
            [
                "dump-resolve",
                ws,
                "--name",
                target,
                "--in-file",
                sink_file,
                "--compact",
                "--format",
                "text",
            ],
            ok=(0, 2),
            nonempty=True,
        )
        append_optional_entry(
            matrix,
            candidate_id,
            "dump-resolve --candidate",
            [
                "dump-resolve",
                ws,
                target,
                "--candidate",
                candidate_id,
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "dump-taint basic",
            ["dump-taint", ws, "--source", entry, "--format", "json"],
            json_out=True,
        )
        add(
            "dump-taint switches",
            [
                "dump-taint",
                ws,
                "--source",
                entry,
                "--seed",
                "cmd",
                "--sink",
                target,
                "--compact",
                "--all",
                "--format",
                "text",
            ],
            nonempty=True,
        )
        append_optional_entry(
            matrix,
            taint_id,
            "dump-taint --taint",
            [
                "dump-taint",
                ws,
                "--source",
                entry,
                "--taint",
                taint_id,
                "--format",
                "json",
            ],
            json_out=True,
        )

        add(
            "defs all switches",
            [
                "defs",
                ws,
                "--kind",
                "function",
                "--file",
                first_file,
                "--name",
                entry[:4],
                "--has-callee",
                target,
                "--has-decorator",
                "decorator",
                "--has-param",
                "cmd",
                "--regex",
                "--limit",
                "5",
                "--no-flows",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "calls all switches",
            [
                "calls",
                ws,
                "--callee",
                target[:4],
                "--file",
                sink_file,
                "--caller",
                entry,
                "--call-kind",
                "function",
                "--regex",
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--no-flows",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "imports all switches",
            [
                "imports",
                ws,
                "--file",
                first_file,
                "--module",
                ".",
                "--alias",
                "x",
                "--wildcard",
                "--regex",
                "--limit",
                "5",
                "--no-flows",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "vars all switches",
            [
                "vars",
                ws,
                "--name",
                "cmd",
                "--file",
                first_file,
                "--in-fn",
                entry,
                "--source",
                "cmd",
                "--regex",
                "--limit",
                "5",
                "--no-flows",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "strings all switches",
            [
                "strings",
                ws,
                "--category",
                "generic",
                "--contains",
                "cmd",
                "--file",
                first_file,
                "--in-fn",
                entry,
                "--min-len",
                "1",
                "--regex",
                "--limit",
                "5",
                "--no-flows",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "comments all switches",
            [
                "comments",
                ws,
                "--kind",
                "generic",
                "--contains",
                "SOURCE|SINK|NEGATIVE",
                "--file",
                first_file,
                "--in-fn",
                entry,
                "--min-len",
                "1",
                "--regex",
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "args all switches",
            [
                "args",
                ws,
                "--callee",
                target[:4],
                "--file",
                sink_file,
                "--in-fn",
                target,
                "--value",
                "cmd",
                "--position",
                "0",
                "--keyword",
                "cmd",
                "--regex",
                "--limit",
                "5",
                "--no-flows",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "classes all switches",
            [
                "classes",
                ws,
                "--name",
                "Envelope",
                "--file",
                first_file,
                "--kind",
                "class",
                "--has-method",
                target,
                "--min-methods",
                "0",
                "--regex",
                "--limit",
                "5",
                "--no-flows",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "refs all switches",
            [
                "refs",
                ws,
                target,
                "--symbol",
                target,
                "--kind",
                "call",
                "--file",
                sink_file,
                "--in-fn",
                target,
                "--regex",
                "--limit",
                "5",
                "--no-flows",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "search all switches",
            [
                "search",
                ws,
                entry,
                "--query",
                entry,
                "--kind",
                "function",
                "--file",
                first_file,
                "--regex",
                "--limit",
                "5",
                "--no-flows",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "tree all switches",
            [
                "tree",
                ws,
                "--max-depth",
                "3",
                "--file",
                first_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--limit",
                "10",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "read-file all switches",
            [
                "read-file",
                ws,
                first_file,
                "--lines",
                "1:50",
                "--from",
                entry,
                "--to",
                target,
                "--max-inlined-bodies",
                "2",
                "--compact",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
                "--rules-dir",
                self.rules_dir,
            ],
            json_out=True,
        )

        add(
            "inspect positional",
            ["inspect", ws, target, "--format", "json", "--all"],
            ok=(0, 1),
            json_out=True,
        )
        add(
            "inspect decl-kind switches",
            [
                "inspect",
                ws,
                "--query",
                entry,
                "--regex",
                "--from",
                entry,
                "--from-kind",
                "decl",
                "--to",
                entry,
                "--to-kind",
                "decl",
                "--max-flows",
                "10",
                "--max-entry-probes",
                "100",
                "--max-hits",
                "50",
                "--all",
                "--compact",
                "--view",
                "auto",
                "--context",
                "4k",
                "--page",
                "1",
                "--format",
                "json",
            ],
            ok=(0, 1),
            json_out=True,
        )
        add(
            "inspect call filters",
            [
                "inspect",
                ws,
                "--query",
                call_filter_query,
                "--kind",
                "call",
                "--file",
                call_filter_file,
                "--in-fn",
                call_filter_fn,
                "--format",
                "json",
                "--all",
            ],
            ok=(0, 1),
            json_out=True,
        )
        add(
            "inspect grouped",
            [
                "inspect",
                ws,
                "--query",
                target,
                "--view",
                "grouped",
                "--format",
                "json",
                "--all",
            ],
            ok=(0, 1),
            json_out=True,
        )
        append_optional_entry(
            matrix,
            flow_id,
            "inspect --flow",
            [
                "inspect",
                ws,
                "--query",
                target,
                "--flow",
                flow_id,
                "--format",
                "json",
            ],
            ok=(0, 1),
            json_out=True,
        )
        append_optional_entry(
            matrix,
            group_id,
            "inspect --group",
            [
                "inspect",
                ws,
                "--query",
                target,
                "--view",
                "grouped",
                "--group",
                group_id,
                "--format",
                "json",
            ],
            ok=(0, 1),
            json_out=True,
        )

        # `--rules-dir` is per-subcommand — it must follow each
        # security subcommand name (sources/sinks/...), not the
        # parent `security` verb.
        sec = ["security", ws]
        rd = ["--rules-dir", self.rules_dir]
        add(
            "security sources switches",
            [
                *sec,
                "sources",
                *rd,
                "--rule",
                source_rule,
                "--rule-regex",
                ".*",
                "--trust",
                "local",
                "--category",
                "inferred",
                "--tag",
                "entry-point",
                "--file",
                source_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "security sinks switches",
            [
                *sec,
                "sinks",
                *rd,
                "--rule",
                sink_rule,
                "--rule-regex",
                ".*",
                "--severity",
                "critical",
                "--tag",
                "command-injection",
                "--file",
                sink_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "security sanitizers switches",
            [
                *sec,
                "sanitizers",
                *rd,
                "--rule",
                "none",
                "--rule-regex",
                ".*",
                "--tag",
                "shell-escape",
                "--file",
                first_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "security deps switches",
            [
                *sec,
                "deps",
                *rd,
                "--framework",
                "none",
                "--severity",
                "critical",
                "--file",
                first_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--limit",
                "5",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "security taint switches",
            [
                *sec,
                "taint-analysis",
                *rd,
                "--source",
                ".*",
                "--trust",
                "local",
                "--category",
                "inferred",
                "--sink",
                ".*",
                "--severity",
                "critical",
                "--tag",
                "command-injection",
                "--file",
                sink_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--inferred-sources",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "security source-analysis switches",
            [
                *sec,
                "source-analysis",
                *rd,
                "--source",
                ".*",
                "--trust",
                "local",
                "--tag",
                "entry-point",
                "--category",
                "inferred",
                "--file",
                source_file,
                "--exclude-file",
                "DOES_NOT_EXIST",
                "--inferred-sources",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add(
            "security pack switches",
            [
                *sec,
                "pack",
                *rd,
                "--lang",
                lang,
                "--category",
                "cmdi",
                "--kind",
                "sink",
                "--severity",
                "critical",
                "--audit",
                "--tree",
                "--context",
                "4k",
                "--page",
                "1",
                "--all",
                "--limit",
                "10",
                "--format",
                "json",
            ],
            json_out=True,
        )
        add("cache stats", ["cache", "stats", ws], nonempty=True)

        with tempfile.TemporaryDirectory(prefix=f"cli_matrix_{lang}_") as temp_dir:
            temp_ws = Path(temp_dir) / "mega_flow"
            shutil.copytree(ws, temp_ws)
            add(
                "cache clear --dataflow-only",
                ["cache", "clear", temp_ws, "--dataflow-only"],
            )
            add("cache rebuild", ["cache", "rebuild", temp_ws])
            add("cache clear", ["cache", "clear", temp_ws])
            for label, args, ok, nonempty, json_out in matrix:
                self.check(
                    lang, label, args, ok=ok, nonempty=nonempty, json_out=json_out
                )

        self.counts.append((lang, len(matrix)))

    def validate_realworld_redis_footers(self) -> None:
        ws = self.root / "examples" / "realworld" / "redis"
        if not ws.exists():
            return
        checks: list[tuple[str, list[Any]]] = [
            ("defs", ["defs", ws]),
            ("calls", ["calls", ws]),
            ("imports", ["imports", ws]),
            ("vars", ["vars", ws]),
            ("strings", ["strings", ws]),
            ("comments", ["comments", ws]),
            ("args", ["args", ws]),
            ("classes", ["classes", ws]),
            ("refs", ["refs", ws, "server"]),
            ("search", ["search", ws, "--query", "strcpy"]),
            ("tree", ["tree", ws]),
            ("read-file", ["read-file", ws, "src/server.c"]),
            ("dump-callgraph", ["dump-callgraph", ws]),
            ("dump-edges", ["dump-edges", ws]),
            ("dump-ast", ["dump-ast", ws, "--file", "src/server.c"]),
            ("inspect", ["inspect", ws, "--query", "strcpy"]),
            ("trace", ["trace", ws, "main"]),
            ("security sources", ["security", ws, "sources"]),
            ("security sinks", ["security", ws, "sinks"]),
            ("security sanitizers", ["security", ws, "sanitizers"]),
            ("security deps", ["security", ws, "deps"]),
            ("security taint-analysis", ["security", ws, "taint-analysis"]),
            ("security source-analysis", ["security", ws, "source-analysis"]),
            ("security pack", ["security", ws, "pack"]),
        ]
        for label, args in checks:
            if "--context" in [str(arg) for arg in args]:
                cmd = [*args, "--no-color", "--no-progress"]
            else:
                cmd = [*args, "--context", "32k", "--no-color", "--no-progress"]
            self.check("realworld/redis", label, cmd, nonempty=True)
        self.counts.append(("realworld/redis footers", len(checks)))

    def report(self) -> int:
        print("COMMAND COUNTS")
        for lang, count in self.counts:
            print(f"{lang}: {count}")
        if not self.failures:
            print("\nALL COMMAND/SWITCH VALIDATION PASSED")
            return 0
        print("\nFAILURES")
        for failure in self.failures[:200]:
            print(f"[{failure.lang}] {failure.label}: {failure.message}")
            print(f"  args={failure.args}")
            if failure.stdout:
                print("  stdout:", failure.stdout.replace("\n", " ")[:900])
            if failure.stderr:
                print("  stderr:", failure.stderr.replace("\n", " ")[:900])
        print(f"total failures: {len(self.failures)}")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", help="Path to bonsai-ninja binary")
    parser.add_argument(
        "--lang",
        action="append",
        choices=LANGS,
        help="Restrict to one language; repeatable",
    )
    parser.add_argument(
        "--skip-realworld",
        action="store_true",
        help="Skip the Redis realworld header/footer stress sweep",
    )
    parser.add_argument(
        "--realworld-only",
        action="store_true",
        help="Run only the Redis realworld header/footer stress sweep",
    )
    args = parser.parse_args()

    root = repo_root()
    validator = Validator(root, find_bin(root, args.bin), root / "security-patterns")
    if not args.realworld_only:
        validator.validate_global()
        for lang in args.lang or LANGS:
            validator.validate_lang(lang)
    if args.realworld_only or not args.skip_realworld:
        validator.validate_realworld_redis_footers()
    return validator.report()


if __name__ == "__main__":
    raise SystemExit(main())
