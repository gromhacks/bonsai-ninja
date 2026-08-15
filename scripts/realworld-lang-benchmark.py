#!/usr/bin/env python3
"""Benchmark real-world repositories across supported languages.

The harness intentionally treats every checkout as disposable: it clones into
`/tmp`, runs the release CLI, validates machine-readable taint output, records
phase timing, and deletes the checkout unless `--keep-workspaces` is passed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LANG_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "c": (".c", ".h"),
    "cpp": (".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"),
    "csharp": (".cs",),
    "dart": (".dart",),
    "elixir": (".ex", ".exs"),
    "erlang": (".erl", ".hrl"),
    "go": (".go",),
    "java": (".java",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "kotlin": (".kt", ".kts"),
    "lua": (".lua",),
    "objc": (".m", ".mm"),
    "perl": (".pl", ".pm", ".t"),
    "php": (".php",),
    "python": (".py",),
    "ruby": (".rb",),
    "rust": (".rs",),
    "scala": (".scala", ".sc"),
    "swift": (".swift",),
    "typescript": (".ts", ".tsx"),
}


SKIP_DIRS = {
    ".git",
    ".bonsai",
    ".bonsai-agent",
    ".gradle",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".stack-work",
    ".venv",
    "__pycache__",
    "bazel-bin",
    "bazel-out",
    "bazel-testlogs",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
}


@dataclass(frozen=True)
class RepoTarget:
    language: str
    name: str
    url: str


TARGETS: tuple[RepoTarget, ...] = (
    RepoTarget("c", "ffmpeg", "https://github.com/FFmpeg/FFmpeg.git"),
    RepoTarget("cpp", "opencv", "https://github.com/opencv/opencv.git"),
    RepoTarget("csharp", "aspnetcore", "https://github.com/dotnet/aspnetcore.git"),
    RepoTarget("dart", "flutter", "https://github.com/flutter/flutter.git"),
    RepoTarget("elixir", "elixir", "https://github.com/elixir-lang/elixir.git"),
    RepoTarget("erlang", "otp", "https://github.com/erlang/otp.git"),
    RepoTarget("go", "kubernetes", "https://github.com/kubernetes/kubernetes.git"),
    RepoTarget(
        "java",
        "spring-framework",
        "https://github.com/spring-projects/spring-framework.git",
    ),
    RepoTarget("javascript", "node", "https://github.com/nodejs/node.git"),
    RepoTarget("kotlin", "kotlin", "https://github.com/JetBrains/kotlin.git"),
    RepoTarget("lua", "kong", "https://github.com/Kong/kong.git"),
    RepoTarget(
        "objc", "firebase-ios-sdk", "https://github.com/firebase/firebase-ios-sdk.git"
    ),
    RepoTarget("perl", "perl5", "https://github.com/Perl/perl5.git"),
    RepoTarget(
        "php", "wordpress-develop", "https://github.com/WordPress/wordpress-develop.git"
    ),
    RepoTarget("python", "ansible", "https://github.com/ansible/ansible.git"),
    RepoTarget("ruby", "rails", "https://github.com/rails/rails.git"),
    RepoTarget("rust", "rust", "https://github.com/rust-lang/rust.git"),
    RepoTarget("scala", "spark", "https://github.com/apache/spark.git"),
    RepoTarget("swift", "swift", "https://github.com/swiftlang/swift.git"),
    RepoTarget("typescript", "vscode", "https://github.com/microsoft/vscode.git"),
)


SECURITY_PHASE_RE = re.compile(
    r"^\[security-phase\]\s+([^:]+):\s+([0-9.]+)s(?:\s+(.*))?$"
)
TIME_RE = re.compile(r"^(real|user|sys)\s+([0-9.]+)$", re.MULTILINE)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def supported_languages(root: Path) -> tuple[str, ...]:
    return tuple(
        sorted(
            path.name
            for path in (root / "security-patterns" / "langs").iterdir()
            if path.is_dir()
        )
    )


def target_inventory_problems(root: Path) -> list[str]:
    """Return drift between compiler adapters, rule data, and benchmark targets."""

    rulepack = set(supported_languages(root))
    adapters = {
        path.name.removeprefix("lang_")
        for path in (root / "crates").glob("lang_*")
        if path.is_dir() and path.name != "lang_api"
    }
    target_counts = Counter(target.language for target in TARGETS)
    targets = set(target_counts)
    extensions = set(LANG_EXTENSIONS)
    problems: list[str] = []

    if adapters != rulepack:
        problems.append(
            "adapter/rulepack language mismatch: "
            f"adapters_only={sorted(adapters - rulepack)}, "
            f"rulepack_only={sorted(rulepack - adapters)}"
        )
    for label, actual in (("targets", targets), ("extension inventories", extensions)):
        if actual != rulepack:
            problems.append(
                f"real-world {label} do not cover the supported languages: "
                f"missing={sorted(rulepack - actual)}, extra={sorted(actual - rulepack)}"
            )
    duplicates = sorted(
        language for language, count in target_counts.items() if count != 1
    )
    if duplicates:
        problems.append(f"languages with duplicate repository targets: {duplicates}")

    names = Counter(target.name for target in TARGETS)
    duplicate_names = sorted(name for name, count in names.items() if count != 1)
    if duplicate_names:
        problems.append(f"duplicate repository target names: {duplicate_names}")
    invalid_urls = sorted(
        target.url
        for target in TARGETS
        if not target.url.startswith("https://github.com/")
        or not target.url.endswith(".git")
    )
    if invalid_urls:
        problems.append(
            f"repository targets must use HTTPS GitHub clone URLs: {invalid_urls}"
        )
    return problems


def find_binary(root: Path, explicit: str | None) -> Path:
    if explicit:
        binary = Path(explicit).expanduser().resolve()
        if not binary.exists():
            raise SystemExit(f"binary not found: {binary}")
        return binary
    candidate = root / "target" / "release" / "bonsai-ninja"
    if candidate.exists():
        return candidate
    raise SystemExit(
        "missing release binary; run `cargo build --release -p bonsai_cli --bin bonsai-ninja`"
    )


def parse_langs(raw: str | None, supported: tuple[str, ...]) -> list[str]:
    if not raw or raw == "all":
        return list(supported)
    langs = [part.strip() for part in raw.split(",") if part.strip()]
    unknown = sorted(set(langs) - set(supported))
    if unknown:
        raise SystemExit(f"unknown language(s): {', '.join(unknown)}")
    return langs


def target_for_language(language: str) -> RepoTarget:
    for target in TARGETS:
        if target.language == language:
            return target
    raise KeyError(language)


def run_command(
    cmd: list[str],
    *,
    cwd: Path,
    timeout: int | None,
    env: dict[str, str] | None = None,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)
    stdout_handle = stdout_path.open("wb") if stdout_path else subprocess.PIPE
    stderr_handle = stderr_path.open("wb") if stderr_path else subprocess.PIPE
    proc: subprocess.CompletedProcess[bytes] | None = None
    try:
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd),
                env=proc_env,
                stdout=stdout_handle,
                stderr=stderr_handle,
                timeout=timeout,
                check=False,
            )
            timed_out = False
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            returncode = None
    finally:
        if stdout_path:
            stdout_handle.close()
        if stderr_path:
            stderr_handle.close()
    elapsed = time.monotonic() - started
    stdout_text = (
        ""
        if stdout_path or proc is None
        else (proc.stdout or b"").decode("utf-8", errors="replace")
    )
    stderr_text = (
        ""
        if stderr_path or proc is None
        else (proc.stderr or b"").decode("utf-8", errors="replace")
    )
    if stderr_path and stderr_path.exists():
        stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    if stdout_path and stdout_path.exists() and stdout_path.stat().st_size < 1_000_000:
        stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace")
    times = {key: float(value) for key, value in TIME_RE.findall(stderr_text)}
    return {
        "cmd": cmd,
        "elapsed_seconds": round(elapsed, 3),
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout_bytes": stdout_path.stat().st_size
        if stdout_path and stdout_path.exists()
        else len(stdout_text.encode()),
        "stderr_bytes": stderr_path.stat().st_size
        if stderr_path and stderr_path.exists()
        else len(stderr_text.encode()),
        "stdout_preview": stdout_text[:2000],
        "stderr_preview": stderr_text[:4000],
        "time": times,
    }


def command_seconds(result: dict[str, Any]) -> float | None:
    real = result.get("time", {}).get("real")
    if isinstance(real, (int, float)):
        return float(real)
    elapsed = result.get("elapsed_seconds")
    if isinstance(elapsed, (int, float)):
        return float(elapsed)
    return None


def clone_repo(target: RepoTarget, dest: Path, timeout: int) -> dict[str, Any]:
    return run_command(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            target.url,
            str(dest),
        ],
        cwd=dest.parent,
        timeout=timeout,
    )


def count_files(workspace: Path, language: str) -> dict[str, Any]:
    exts = LANG_EXTENSIONS[language]
    totals: dict[str, int] = {}
    total_files = 0
    language_files = 0
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        for name in files:
            total_files += 1
            suffix = Path(name).suffix.lower()
            if suffix:
                totals[suffix] = totals.get(suffix, 0) + 1
            if suffix in exts:
                language_files += 1
    return {
        "total_files": total_files,
        "language_files": language_files,
        "extensions": {key: totals[key] for key in sorted(totals) if key in exts},
    }


def parse_phase_log(stderr_text: str) -> dict[str, Any]:
    phases: dict[str, Any] = {}
    for line in stderr_text.splitlines():
        match = SECURITY_PHASE_RE.match(line)
        if not match:
            continue
        name, seconds, raw_meta = match.groups()
        meta: dict[str, Any] = {"seconds": float(seconds)}
        if raw_meta:
            for token in raw_meta.split():
                if "=" not in token:
                    continue
                key, value = token.split("=", 1)
                if value.isdigit():
                    meta[key] = int(value)
                elif value in {"true", "false"}:
                    meta[key] = value == "true"
                else:
                    meta[key] = value
        phases[name] = meta
    return phases


def is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def load_finding_rows(json_path: Path) -> tuple[list[Any] | None, list[str], bool]:
    try:
        data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return None, [f"invalid json: {exc}"], False
    problems = []
    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        if data.get("analysis_complete") is not True:
            problems.append("top-level analysis_complete != true")
        data = data["rows"]
    if not isinstance(data, list):
        problems.append(
            f"expected list output or rows object, got {type(data).__name__}"
        )
        return None, problems, True
    return data, problems, True


def increment(counts: dict[str, int], value: object) -> None:
    if isinstance(value, str) and value:
        counts[value] = counts.get(value, 0) + 1


def validate_file_path(
    *,
    file_value: object,
    workspace: Path,
    finding_index: int,
    label: str,
    problems: list[str],
) -> int:
    if not isinstance(file_value, str) or not file_value:
        return 0
    path = Path(file_value)
    if not is_under(path, workspace):
        problems.append(
            f"finding {finding_index}: {label} file outside workspace: {file_value}"
        )
    elif not path.exists():
        problems.append(f"finding {finding_index}: {label} file missing: {file_value}")
    return 1


def validate_endpoint(
    *,
    finding: dict[str, Any],
    label: str,
    finding_index: int,
    workspace: Path,
    rule_counts: dict[str, int],
    severity_counts: dict[str, int],
    problems: list[str],
) -> int:
    item = finding.get(label)
    if not isinstance(item, dict):
        problems.append(f"finding {finding_index}: missing {label}")
        return 0
    increment(rule_counts, item.get("rule_id"))
    if label == "sink":
        increment(severity_counts, item.get("severity"))
    return validate_file_path(
        file_value=item.get("file"),
        workspace=workspace,
        finding_index=finding_index,
        label=label,
        problems=problems,
    )


def validate_taint_paths(
    finding: dict[str, Any],
    finding_index: int,
    workspace: Path,
    problems: list[str],
) -> int:
    checked = 0
    for step in finding.get("taint_path", []):
        if isinstance(step, dict):
            checked += validate_file_path(
                file_value=step.get("file"),
                workspace=workspace,
                finding_index=finding_index,
                label="taint path",
                problems=problems,
            )
    return checked


def validate_finding(
    *,
    finding: object,
    index: int,
    workspace: Path,
    counts: dict[str, dict[str, int]],
    problems: list[str],
) -> tuple[int, int]:
    if not isinstance(finding, dict):
        problems.append(f"finding {index}: expected object")
        return 0, 0
    finding_id = finding.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.startswith("S:"):
        problems.append(f"finding {index}: missing stable finding_id")
    increment(counts["language"], finding.get("language"))
    increment(counts["precision"], finding.get("precision"))
    checked = validate_endpoint(
        finding=finding,
        label="source",
        finding_index=index,
        workspace=workspace,
        rule_counts=counts["source_rules"],
        severity_counts=counts["severity"],
        problems=problems,
    )
    checked += validate_endpoint(
        finding=finding,
        label="sink",
        finding_index=index,
        workspace=workspace,
        rule_counts=counts["sink_rules"],
        severity_counts=counts["severity"],
        problems=problems,
    )
    checked += validate_taint_paths(finding, index, workspace, problems)
    incomplete = int(finding.get("analysis_complete") is not True)
    return checked, incomplete


def top_counts(counts: dict[str, int]) -> dict[str, int]:
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:10])


def validate_findings(
    json_path: Path, workspace: Path, primary_language: str
) -> dict[str, Any]:
    data, problems, valid_json = load_finding_rows(json_path)
    if data is None:
        return {
            "valid_json": valid_json,
            "finding_count": None,
            "problems": problems,
        }
    counts: dict[str, dict[str, int]] = {
        "language": {},
        "severity": {},
        "precision": {},
        "source_rules": {},
        "sink_rules": {},
    }
    checked_paths = 0
    incomplete = 0
    for index, finding in enumerate(data):
        checked, finding_incomplete = validate_finding(
            finding=finding,
            index=index,
            workspace=workspace,
            counts=counts,
            problems=problems,
        )
        checked_paths += checked
        incomplete += finding_incomplete
    if incomplete:
        problems.append(f"{incomplete} finding(s) had analysis_complete != true")
    return {
        "valid_json": True,
        "finding_count": len(data),
        "primary_language_findings": counts["language"].get(primary_language, 0),
        "language_counts": dict(sorted(counts["language"].items())),
        "severity_counts": dict(sorted(counts["severity"].items())),
        "precision_counts": dict(sorted(counts["precision"].items())),
        "top_source_rules": top_counts(counts["source_rules"]),
        "top_sink_rules": top_counts(counts["sink_rules"]),
        "checked_paths": checked_paths,
        "problems": problems[:200],
    }


def run_target(
    target: RepoTarget,
    *,
    binary: Path,
    tmp_root: Path,
    out_dir: Path,
    clone_timeout: int,
    command_timeout: int | None,
    profile: str | None,
    paged_output: bool,
    keep_workspaces: bool,
) -> dict[str, Any]:
    temp_path = Path(
        tempfile.mkdtemp(
            prefix=f"bonsai-realworld-{target.language}-", dir=str(tmp_root)
        )
    )
    workspace = temp_path / target.name
    result: dict[str, Any] = {
        "language": target.language,
        "name": target.name,
        "url": target.url,
        "profile": profile,
        "paged_output": paged_output,
        "workspace": str(workspace),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        clone = clone_repo(target, workspace, clone_timeout)
        result["clone"] = clone
        if clone["returncode"] != 0 or clone["timed_out"]:
            result["status"] = "clone_failed"
            return result
        result["file_counts"] = count_files(workspace, target.language)

        index_stdout = out_dir / f"{target.language}-{target.name}-index.out"
        index_stderr = out_dir / f"{target.language}-{target.name}-index.err"
        index = run_command(
            [str(binary), "index", str(workspace), "--no-color", "--no-progress"],
            cwd=repo_root(),
            timeout=command_timeout,
            stdout_path=index_stdout,
            stderr_path=index_stderr,
        )
        result["index"] = index
        if index["returncode"] != 0 or index["timed_out"]:
            result["status"] = "index_failed"
            return result

        taint_json = out_dir / f"{target.language}-{target.name}-taint.json"
        taint_stderr = out_dir / f"{target.language}-{target.name}-taint.err"
        taint_cmd = [
            str(binary),
            "security",
            str(workspace),
            "taint-analysis",
            "--format",
            "json",
            "--no-color",
            "--no-progress",
        ]
        if profile:
            taint_cmd.extend(["--profile", profile])
        if not paged_output:
            taint_cmd.append("--all")
        taint = run_command(
            taint_cmd,
            cwd=repo_root(),
            timeout=command_timeout,
            env={"BONSAI_DEBUG": "security-phase"},
            stdout_path=taint_json,
            stderr_path=taint_stderr,
        )
        stderr_text = (
            taint_stderr.read_text(encoding="utf-8", errors="replace")
            if taint_stderr.exists()
            else ""
        )
        taint["phases"] = parse_phase_log(stderr_text)
        taint["warnings"] = [
            text
            for text in (
                "payload exceeds 4GiB",
                "save_to_disk failed",
                "workspace IDG save_to_disk failed",
            )
            if text in stderr_text
        ]
        result["taint"] = taint
        if taint["returncode"] != 0 or taint["timed_out"]:
            result["status"] = "taint_failed"
            return result
        validation = validate_findings(taint_json, workspace, target.language)
        result["validation"] = validation
        if taint["warnings"] or validation.get("problems"):
            result["status"] = "validation_failed"
        else:
            result["status"] = "ok"
        return result
    finally:
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        if keep_workspaces:
            result["workspace_kept"] = True
        else:
            shutil.rmtree(temp_path, ignore_errors=True)
            result["workspace_deleted"] = True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate language and repository-target coverage without cloning",
    )
    parser.add_argument("--bin", dest="binary", help="bonsai-ninja binary path")
    parser.add_argument(
        "--langs", default="all", help="comma-separated language list, or all"
    )
    parser.add_argument("--tmp-root", default="/tmp", help="temporary clone parent")
    parser.add_argument(
        "--out-dir",
        default=None,
        help="artifact directory, default target/realworld-lang-benchmark",
    )
    parser.add_argument("--json-out", default=None, help="summary JSON path")
    parser.add_argument("--clone-timeout", type=int, default=900)
    parser.add_argument(
        "--command-timeout",
        type=int,
        default=None,
        help="optional per-analysis-command timeout in seconds; uncapped by default",
    )
    parser.add_argument(
        "--profile",
        default="production",
        help="security profile for taint-analysis; empty disables",
    )
    parser.add_argument(
        "--paged-output",
        action="store_true",
        help="keep paged JSON instead of passing --all",
    )
    parser.add_argument("--keep-workspaces", action="store_true")
    parser.add_argument("--continue-on-error", action="store_true")
    args = parser.parse_args(argv)

    root = repo_root()
    inventory_problems = target_inventory_problems(root)
    if inventory_problems:
        for problem in inventory_problems:
            print(f"real-world benchmark inventory: {problem}", file=sys.stderr)
        return 1
    supported = supported_languages(root)
    if args.check:
        print(
            "real-world benchmark inventory: "
            f"{len(supported)} supported languages and repository targets are consistent"
        )
        return 0

    binary = find_binary(root, args.binary)
    langs = parse_langs(args.langs, supported)
    tmp_root = Path(args.tmp_root).expanduser().resolve()
    tmp_root.mkdir(parents=True, exist_ok=True)
    out_dir = (
        Path(args.out_dir).expanduser().resolve()
        if args.out_dir
        else root / "target" / "realworld-lang-benchmark"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    json_out = (
        Path(args.json_out).expanduser().resolve()
        if args.json_out
        else out_dir
        / f"summary-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    )

    results: list[dict[str, Any]] = []
    for language in langs:
        target = target_for_language(language)
        print(
            f"[realworld-bench] {language}: cloning and benchmarking {target.name}",
            flush=True,
        )
        result = run_target(
            target,
            binary=binary,
            tmp_root=tmp_root,
            out_dir=out_dir,
            clone_timeout=args.clone_timeout,
            command_timeout=args.command_timeout,
            profile=args.profile or None,
            paged_output=args.paged_output,
            keep_workspaces=args.keep_workspaces,
        )
        results.append(result)
        interim_failures = [
            item["language"] for item in results if item.get("status") != "ok"
        ]
        json_out.write_text(
            json.dumps(
                {"results": results, "failures": interim_failures},
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        status = result.get("status")
        findings = result.get("validation", {}).get("finding_count")
        index_seconds = command_seconds(result.get("index", {}))
        taint_seconds = command_seconds(result.get("taint", {}))
        print(
            f"[realworld-bench] {language}: status={status} index={index_seconds}s taint={taint_seconds}s findings={findings}",
            flush=True,
        )
        if status != "ok" and not args.continue_on_error:
            break

    failures = [item for item in results if item.get("status") != "ok"]
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "binary": str(binary),
        "results": results,
        "failures": [item["language"] for item in failures],
    }
    json_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(f"[realworld-bench] wrote {json_out}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
