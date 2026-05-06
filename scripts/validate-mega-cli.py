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
import sys
import tempfile
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
    # These are raw propagated source-to-sink findings. Sanitizers are
    # reported as evidence on matching paths; they do not suppress the
    # path or change the expected raw count.
    # C reports the command sink plus every bounded string-copy/append
    # sink site reached from argv in the construct-coverage fixture.
    "c": 11,
    # JS reports the single real stdin/readline command-injection chain.
    # Constant clean-twin sinks and duplicate inferred entry rows are not
    # counted as separate findings.
    "javascript": 1,
    # Lua bumped from 1 → 3 with the rule-pack expansion (lua.sqli.luasql_execute
    # now matches both `.execute` and `:execute` shapes via the receiver
    # alternation `^(conn|cur|cursor|stmt|db|env|database|connection|sql)[.:]execute$`;
    # the receiver alternation prevents collisions with stdlib `os.execute(cmd)`).
    "lua": 3,
    "objc": 2,
    # Python reports the real command-injection/data-return rows plus
    # opt-in inferred entry-point rows on callable hops that directly
    # forward into os.system.
    "python": 5,
    # ruby rose from 1 → 2 with the cross-file recall landing.
    # `ruby.source.bytes_blob_param` fires on `wrap(blob)` in
    # storage.rb; the result reaches executor.rb's `execute` which
    # calls `Kernel.system`. Real cross-file flow newly captured via
    # `InterTaintConfig.source_bearing_functions`.
    "ruby": 2,
    # Solidity includes the inferred external-call-data reentrancy path,
    # msg.sender/calldata event payload flows, and derived event length
    # payload flows from the same handle path.
    "solidity": 5,
    # Swift reports the Process.arguments write reached by readLine(); the
    # launch/launchPath rows are sink inventory, but not tainted in the full
    # source-to-sink chain.
    "swift": 1,
    # TS reports the single real readline command-injection chain.
    # Constant clean-twin sinks and duplicate inferred entry rows are not
    # counted as separate findings.
    "typescript": 1,
    "dart": 2,
    # Go reports the explicit request-header source plus the opt-in
    # inferred request parameter source through the same shell wrapper.
    "go": 2,
}

CONTEXT_FOOTER_RE = re.compile(r"context\s+~?([0-9,]+) / ([0-9,]+) tokens \((\d+)%\)")
PAGE_FOOTER_RE = re.compile(r"^page\s+\d+\s+of\s+[0-9,]+\s+\([0-9,]+\s+rows\)", re.MULTILINE)
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

    def validate_text_footer(self, lang: str, label: str, args: list[str], stdout: str) -> None:
        lines = [line for line in stdout.splitlines() if line.strip()]
        if not lines:
            return
        if lines[0].startswith(("page ", "context ", "next ")):
            self.failures.append(Failure(lang, label, args, f"footer appeared before command output: {lines[0]}"))
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
        self.check("global", "theme help", ["--theme", "dracula", "--help"], nonempty=True)

    def validate_lang(self, lang: str) -> None:
        ws = self.root / "examples" / lang / "mega_flow"
        if not ws.exists():
            self.failures.append(Failure(lang, "workspace", [str(ws)], "missing mega_flow"))
            return

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
                # Inferred entry-point sources are opt-in at the CLI by
                # default (per `--inferred-sources` semantics). The
                # mega-flow expectations were authored against the
                # inferred-on surface, so the validator opts in.
                "--inferred-sources",
                "--format",
                "json",
                "--all",
            ],
            json_out=True,
        )
        if not isinstance(taint, list) or len(taint) != expected_findings:
            got = len(taint) if isinstance(taint, list) else "?"
            self.failures.append(
                Failure(lang, "derive taint", ["security", str(ws), "taint-analysis"], f"expected {expected_findings} findings, got {got}")
            )
            return
        if lang == "python" and any(
            row.get("source", {}).get("rule_id") == "entry-point.decorator_handler.param_0"
            and row.get("source", {}).get("enclosing_fn") == "run_pipeline"
            for row in taint
        ):
            self.failures.append(
                Failure(
                    lang,
                    "derive taint",
                    ["security", str(ws), "taint-analysis"],
                    "undecorated run_pipeline inherited handle_request decorators",
                )
            )
            return

        first = taint[0]
        chain = first.get("chain_display") or []
        entry = chain[0] if chain else first.get("source", {}).get("enclosing_fn")
        target = first.get("sink", {}).get("enclosing_fn") or (chain[-1] if chain else entry)
        sink_text = first.get("sink", {}).get("text") or target
        source_rule = first.get("source", {}).get("rule_id", ".")
        sink_rule = first.get("sink", {}).get("rule_id", ".")
        source_file = Path(first.get("source", {}).get("file", "app")).name
        sink_file = Path(first.get("sink", {}).get("file", "executor")).name
        call_filter_query = sink_text
        call_filter_file = sink_file
        call_filter_fn = target
        for step in reversed(first.get("taint_path") or []):
            if not isinstance(step, dict):
                continue
            callee = step.get("callee")
            caller = step.get("caller")
            call_file = step.get("file")
            if callee == target and isinstance(caller, str) and isinstance(call_file, str):
                call_filter_query = callee
                call_filter_file = Path(call_file).name
                call_filter_fn = caller
                break
        if not entry or not target:
            self.failures.append(Failure(lang, "derive symbols", [str(ws)], "missing entry/target"))
            return

        export = self.check(lang, "export derive", ["export", ws], json_out=True)
        files = export_files(export)
        first_file = Path(files[0]).name if files else source_file

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

        edges = self.check(lang, "edges derive", ["dump-edges", ws, "--format", "json", "--all"], json_out=True)
        edge_id = edges[0].get("edge_id") if isinstance(edges, list) and edges else None

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
        candidate_id = None
        if isinstance(resolve, dict) and resolve.get("candidates"):
            candidate_id = resolve["candidates"][0].get("candidate_id")

        dump_taint = self.check(
            lang,
            "dump-taint derive",
            ["dump-taint", ws, "--source", entry, "--format", "json"],
            json_out=True,
        )
        taint_id = None
        if isinstance(dump_taint, dict) and dump_taint.get("records"):
            taint_id = dump_taint["records"][0].get("taint_id")

        matrix: list[tuple[str, list[Any], tuple[int, ...], bool, bool]] = []

        def add(
            label: str,
            args: list[Any],
            *,
            ok: tuple[int, ...] = (0,),
            nonempty: bool = False,
            json_out: bool = False,
        ) -> None:
            matrix.append((label, args, ok, nonempty, json_out))

        add("global --no-color", ["--no-color", "defs", ws, "--limit", "1"], nonempty=True)
        add("global --no-cache", ["--no-cache", "inspect", ws, "--query", target, "--format", "json", "--all"], ok=(0, 1), json_out=True)
        add("global --no-progress", ["--no-progress", "security", ws, "taint-analysis", "--rules-dir", self.rules_dir, "--format", "json", "--all"], json_out=True)
        add("global --theme", ["--theme", "retro-amber", "calls", ws, "--limit", "1"], nonempty=True)
        add("index", ["index", ws], nonempty=True)
        add("export", ["export", ws], json_out=True)
        add("export --full-propagations", ["export", ws, "--full-propagations"], json_out=True)
        add("trace positional json", ["trace", ws, entry, "--format", "json"], json_out=True)
        add("trace --function", ["trace", ws, "--function", entry, "--format", "json"], json_out=True)
        add("trace --from --to", ["trace", ws, "--from", entry, "--to", target, "--format", "json"], json_out=True)
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
        add("dump-callgraph json", ["dump-callgraph", ws, "--format", "json", "--all"], json_out=True)
        add("dump-callgraph switches", ["dump-callgraph", ws, "--limit", "5", "--context", "4k", "--page", "1", "--format", "text"], nonempty=True)
        add("dump-edges json", ["dump-edges", ws, "--format", "json", "--all"], json_out=True)
        add("dump-edges switches", ["dump-edges", ws, "--from", entry, "--to", target, "--precision", "exact", "--compact", "--limit", "10", "--context", "4k", "--page", "1", "--format", "text"], nonempty=True)
        if edge_id:
            add("dump-edges --edge", ["dump-edges", ws, "--edge", edge_id, "--format", "json"], json_out=True)
        add("dump-ast positional", ["dump-ast", ws, entry, "--format", "json", "--all"], json_out=True)
        add("dump-ast file switches", ["dump-ast", ws, "--file", first_file, "--compact", "--max-depth", "3", "--limit", "2", "--context", "4k", "--page", "1", "--format", "text"], nonempty=True)
        add("dump-ast --function", ["dump-ast", ws, "--function", entry, "--format", "json"], json_out=True)
        if node_id:
            add("dump-ast --node", ["dump-ast", ws, "--node", node_id, "--format", "json"], json_out=True)
        add("dump-resolve positional", ["dump-resolve", ws, target, "--format", "json"], ok=(0, 2), json_out=True)
        add("dump-resolve switches", ["dump-resolve", ws, "--name", target, "--in-file", sink_file, "--compact", "--format", "text"], ok=(0, 2), nonempty=True)
        if candidate_id:
            add("dump-resolve --candidate", ["dump-resolve", ws, target, "--candidate", candidate_id, "--format", "json"], json_out=True)
        add("dump-taint basic", ["dump-taint", ws, "--source", entry, "--format", "json"], json_out=True)
        add("dump-taint switches", ["dump-taint", ws, "--source", entry, "--seed", "cmd", "--sanitizer", "clean_twin", "--sink", target, "--budget", "64", "--compact", "--format", "text"], nonempty=True)
        if taint_id:
            add("dump-taint --taint", ["dump-taint", ws, "--source", entry, "--taint", taint_id, "--format", "json"], json_out=True)

        add("defs all switches", ["defs", ws, "--kind", "function", "--file", first_file, "--name", entry[:4], "--has-callee", target, "--has-decorator", "decorator", "--has-param", "cmd", "--regex", "--limit", "5", "--no-flows", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("calls all switches", ["calls", ws, "--callee", target[:4], "--file", sink_file, "--caller", entry, "--call-kind", "function", "--regex", "--limit", "5", "--context", "4k", "--page", "1", "--all", "--no-flows", "--format", "json"], json_out=True)
        add("imports all switches", ["imports", ws, "--file", first_file, "--module", ".", "--alias", "x", "--wildcard", "--regex", "--limit", "5", "--no-flows", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("vars all switches", ["vars", ws, "--name", "cmd", "--file", first_file, "--in-fn", entry, "--source", "cmd", "--regex", "--limit", "5", "--no-flows", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("strings all switches", ["strings", ws, "--category", "generic", "--contains", "cmd", "--file", first_file, "--in-fn", entry, "--min-len", "1", "--regex", "--limit", "5", "--no-flows", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("comments all switches", ["comments", ws, "--kind", "generic", "--contains", "SOURCE|SINK|NEGATIVE", "--file", first_file, "--in-fn", entry, "--min-len", "1", "--regex", "--limit", "5", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("args all switches", ["args", ws, "--callee", target[:4], "--file", sink_file, "--in-fn", target, "--value", "cmd", "--position", "0", "--keyword", "cmd", "--regex", "--limit", "5", "--no-flows", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("classes all switches", ["classes", ws, "--name", "Envelope", "--file", first_file, "--kind", "class", "--has-method", target, "--min-methods", "0", "--regex", "--limit", "5", "--no-flows", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("refs all switches", ["refs", ws, target, "--symbol", target, "--kind", "call", "--file", sink_file, "--in-fn", target, "--regex", "--limit", "5", "--no-flows", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("search all switches", ["search", ws, entry, "--query", entry, "--kind", "function", "--file", first_file, "--regex", "--limit", "5", "--no-flows", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("tree all switches", ["tree", ws, "--max-depth", "3", "--file", first_file, "--exclude-file", "DOES_NOT_EXIST", "--limit", "10", "--compact", "--context", "4k", "--page", "1", "--all", "--format", "json", "--rules-dir", self.rules_dir], json_out=True)
        add("read-file all switches", ["read-file", ws, first_file, "--lines", "1:50", "--from", entry, "--to", target, "--max-inlined-bodies", "2", "--compact", "--context", "4k", "--page", "1", "--all", "--format", "json", "--rules-dir", self.rules_dir], json_out=True)

        add("inspect positional", ["inspect", ws, target, "--format", "json", "--all"], ok=(0, 1), json_out=True)
        add("inspect decl-kind switches", ["inspect", ws, "--query", entry, "--symbol", entry, "--regex", "--from", entry, "--from-kind", "decl", "--to", entry, "--to-kind", "decl", "--max-flows", "10", "--max-entry-probes", "100", "--max-hits", "50", "--all", "--compact", "--view", "auto", "--context", "4k", "--page", "1", "--format", "json"], ok=(0, 1), json_out=True)
        add("inspect call filters", ["inspect", ws, "--query", call_filter_query, "--kind", "call", "--file", call_filter_file, "--in-fn", call_filter_fn, "--format", "json", "--all"], ok=(0, 1), json_out=True)
        add("inspect grouped", ["inspect", ws, "--query", target, "--view", "grouped", "--format", "json", "--all"], ok=(0, 1), json_out=True)
        if flow_id:
            add("inspect --flow", ["inspect", ws, "--query", target, "--flow", flow_id, "--format", "json"], ok=(0, 1), json_out=True)
        if group_id:
            add("inspect --group", ["inspect", ws, "--query", target, "--view", "grouped", "--group", group_id, "--format", "json"], ok=(0, 1), json_out=True)

        # `--rules-dir` is per-subcommand — it must follow each
        # security subcommand name (sources/sinks/...), not the
        # parent `security` verb.
        sec = ["security", ws]
        rd = ["--rules-dir", self.rules_dir]
        add("security sources switches", [*sec, "sources", *rd, "--rule", source_rule, "--rule-regex", ".*", "--trust", "local", "--category", "inferred", "--tag", "entry-point", "--file", source_file, "--exclude-file", "DOES_NOT_EXIST", "--limit", "5", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("security sinks switches", [*sec, "sinks", *rd, "--rule", sink_rule, "--rule-regex", ".*", "--severity", "critical", "--tag", "command-injection", "--file", sink_file, "--exclude-file", "DOES_NOT_EXIST", "--limit", "5", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("security sanitizers switches", [*sec, "sanitizers", *rd, "--rule", "none", "--rule-regex", ".*", "--tag", "shell-escape", "--file", first_file, "--exclude-file", "DOES_NOT_EXIST", "--limit", "5", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("security deps switches", [*sec, "deps", *rd, "--framework", "none", "--severity", "critical", "--file", first_file, "--exclude-file", "DOES_NOT_EXIST", "--limit", "5", "--context", "4k", "--page", "1", "--all", "--format", "json"], json_out=True)
        add("security taint switches", [*sec, "taint-analysis", *rd, "--source", ".*", "--trust", "local", "--category", "inferred", "--sink", ".*", "--severity", "critical", "--tag", "command-injection", "--file", sink_file, "--exclude-file", "DOES_NOT_EXIST", "--inferred-sources", "--context", "4k", "--page", "1", "--all", "--no-compact", "--format", "json"], json_out=True)
        add("security source-analysis switches", [*sec, "source-analysis", *rd, "--source", ".*", "--trust", "local", "--tag", "entry-point", "--category", "inferred", "--file", source_file, "--exclude-file", "DOES_NOT_EXIST", "--inferred-sources", "--context", "4k", "--page", "1", "--all", "--no-compact", "--format", "json"], json_out=True)
        add("security pack switches", [*sec, "pack", *rd, "--lang", lang, "--category", "cmdi", "--kind", "sink", "--severity", "critical", "--audit", "--tree", "--context", "4k", "--page", "1", "--all", "--limit", "10", "--format", "json"], json_out=True)
        add("cache stats", ["cache", "stats", ws], nonempty=True)

        with tempfile.TemporaryDirectory(prefix=f"cli_matrix_{lang}_") as temp_dir:
            temp_ws = Path(temp_dir) / "mega_flow"
            shutil.copytree(ws, temp_ws)
            add("cache clear --dataflow-only", ["cache", "clear", temp_ws, "--dataflow-only"])
            add("cache rebuild", ["cache", "rebuild", temp_ws])
            add("cache clear", ["cache", "clear", temp_ws])
            for label, args, ok, nonempty, json_out in matrix:
                self.check(lang, label, args, ok=ok, nonempty=nonempty, json_out=json_out)

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
            (
                "security taint-analysis --no-compact",
                ["security", ws, "taint-analysis", "--no-compact", "--context", "4k"],
            ),
            ("security source-analysis", ["security", ws, "source-analysis"]),
            (
                "security source-analysis --no-compact",
                ["security", ws, "source-analysis", "--no-compact", "--context", "4k"],
            ),
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
    parser.add_argument("--lang", action="append", choices=LANGS, help="Restrict to one language; repeatable")
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
