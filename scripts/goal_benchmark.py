#!/usr/bin/env python3
"""Cold/warm benchmark harness for docs/goal.md.

The goal explicitly asks us to track parse/index time, callgraph time,
summary/taint time, peak RSS where feasible, cache behavior, and finding
counts on `examples/` and on large local targets when they are available.

This script runs the release CLI as a black-box benchmark and writes one JSON
report that is suitable for check-in, CI artifacts, or local regression notes.
By default it benchmarks a temporary copy of `examples/` so cold-cache setup
does not delete a developer's working `.bonsai/` directory. Large targets can
be supplied explicitly with `--target name=path`, or through
`BONSAI_BENCH_REDIS` / `BONSAI_BENCH_OWASP`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


TIME_RE_MAC = re.compile(r"^\s*(\d+)\s+maximum resident set size$", re.MULTILINE)
TIME_RE_GNU = re.compile(r"^\s*Maximum resident set size \(kbytes\):\s*(\d+)\s*$", re.MULTILINE)
EXPORT_PHASE_RE = re.compile(r"^\[export-phase\]\s+([^:]+):\s+([0-9.]+)s(?:\s+(.*))?$")


@dataclass(frozen=True)
class Target:
    name: str
    path: Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def find_binary(root: Path, explicit: str | None) -> Path:
    if explicit:
        binary = Path(explicit).expanduser().resolve()
        if not binary.exists():
            raise SystemExit(f"binary not found: {binary}")
        return binary
    for candidate in (
        root / "target" / "release" / "bonsai-ninja",
        root / "target" / "debug" / "bonsai-ninja",
    ):
        if candidate.exists():
            return candidate
    raise SystemExit("missing bonsai-ninja binary; run `cargo build --release -p bonsai_cli`")


def parse_target(value: str) -> Target:
    if "=" not in value:
        path = Path(value).expanduser().resolve()
        return Target(path.name or "target", path)
    name, raw_path = value.split("=", 1)
    name = name.strip()
    if not name:
        raise argparse.ArgumentTypeError("target name cannot be empty")
    return Target(name, Path(raw_path).expanduser().resolve())


def env_targets() -> list[Target]:
    out: list[Target] = []
    for name, key in (("redis", "BONSAI_BENCH_REDIS"), ("owasp", "BONSAI_BENCH_OWASP")):
        raw = os.environ.get(key)
        if raw:
            out.append(Target(name, Path(raw).expanduser().resolve()))
    return out


def default_targets(root: Path) -> list[Target]:
    return [Target("examples", root / "examples"), *env_targets()]


def discover_large_targets(root: Path) -> list[Target]:
    candidates: list[Target] = []
    search_roots = [root.parent, root.parent.parent]
    seen: set[Path] = set()
    for base in search_roots:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path in seen or not path.is_dir():
                continue
            seen.add(path)
            lowered = path.name.lower()
            if lowered == "redis":
                candidates.append(Target("redis", path.resolve()))
            elif "owasp" in lowered and "benchmark" in lowered:
                candidates.append(Target("owasp", path.resolve()))
    return candidates


def copy_workspace(src: Path, label: str) -> tuple[Path, tempfile.TemporaryDirectory[str]]:
    temp = tempfile.TemporaryDirectory(prefix=f"bonsai-bench-{label}-")
    dst = Path(temp.name) / src.name
    ignore = shutil.ignore_patterns(
        ".git",
        ".bonsai",
        "target",
        "node_modules",
        ".gradle",
        "build",
        "dist",
        "__pycache__",
    )
    shutil.copytree(src, dst, ignore=ignore, symlinks=True)
    return dst, temp


def time_style() -> list[str] | None:
    time_bin = Path("/usr/bin/time")
    if not time_bin.exists():
        return None
    for args in (["/usr/bin/time", "-l"], ["/usr/bin/time", "-v"]):
        proc = subprocess.run(
            [*args, "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if proc.returncode == 0:
            return args
    return None


def parse_rss_bytes(stderr: str) -> int | None:
    if match := TIME_RE_MAC.search(stderr):
        return int(match.group(1))
    if match := TIME_RE_GNU.search(stderr):
        return int(match.group(1)) * 1024
    return None


def json_from_file(path: Path) -> Any | None:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def count_json_rows(value: Any) -> int | None:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("findings", "candidates", "rows", "files"):
            nested = value.get(key)
            if isinstance(nested, list):
                return len(nested)
    return None


def rows_for_summary(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("findings", "candidates", "rows", "files"):
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
    return []


def count_object_field(rows: list[Any], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        value = row.get(field)
        if value is None and isinstance(row.get("finding"), dict):
            value = row["finding"].get(field)
        if value is None:
            continue
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def summarize_json(value: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {"type": type(value).__name__}
    rows = count_json_rows(value)
    if rows is not None:
        summary["row_count"] = rows
    row_values = rows_for_summary(value)
    if row_values:
        for field in ("precision", "severity", "kind"):
            counts = count_object_field(row_values, field)
            if counts:
                summary[f"{field}_counts"] = counts
    if isinstance(value, dict):
        summary["keys"] = sorted(value.keys())
        for key in (
            "files",
            "classes",
            "callgraph",
            "flow_chains",
            "flow_graph",
            "findings",
            "candidates",
            "rows",
        ):
            nested = value.get(key)
            if isinstance(nested, list):
                summary[f"{key}_count"] = len(nested)
        taint_graph = value.get("taint_graph")
        if isinstance(taint_graph, dict):
            analysis_scope = value.get("analysis_scope")
            if isinstance(analysis_scope, dict):
                summary["analysis_scope"] = analysis_scope
            summary["taint_graph"] = {
                f"{key}_count": len(nested)
                for key, nested in taint_graph.items()
                if isinstance(nested, list)
            }
        for key in (
            "analysis_complete",
            "flow_chains_complete",
            "flow_chains_mode",
            "flow_chains_truncated_targets",
            "propagations_complete",
            "chains_complete",
            "chains_mode",
            "flow_id_labels_complete",
            "flow_id_labels_mode",
            "chains_truncated_targets",
            "flow_id_labels_truncated_functions",
        ):
            if key in value:
                summary[key] = value[key]
            elif isinstance(taint_graph, dict) and key in taint_graph:
                summary["taint_graph"][key] = taint_graph[key]
    return summary


def parse_scalar(raw: str) -> Any:
    if raw == "true":
        return True
    if raw == "false":
        return False
    if raw.endswith("s"):
        try:
            return float(raw[:-1])
        except ValueError:
            pass
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw


def int_value(value: Any, default: int = 0) -> int:
    return value if isinstance(value, int) else default


CACHE_ARTIFACTS: tuple[tuple[str, str, str], ...] = (
    ("dataflow_legacy", "dataflow_sidecar_exists", "dataflow_sidecar_bytes"),
    ("dataflow_factstore", "dataflow_factstore_sidecar_exists", "dataflow_factstore_sidecar_bytes"),
    ("value_flow", "value_flow_sidecar_exists", "value_flow_sidecar_bytes"),
    ("flow_ids", "flow_ids_sidecar_exists", "flow_ids_sidecar_bytes"),
    ("callgraph", "callgraph_sidecar_exists", "callgraph_sidecar_bytes"),
    ("idg", "idg_sidecar_exists", "idg_sidecar_bytes"),
    ("taint_graph", "taint_graph_sidecar_exists", "taint_graph_sidecar_bytes"),
    ("export", "export_sidecar_exists", "export_sidecar_bytes"),
)


def summarize_cache_stats(stats: Any) -> dict[str, Any]:
    if not isinstance(stats, dict):
        return {"available": False, "error": f"unexpected cache stats type: {type(stats).__name__}"}
    if "error" in stats:
        error = stats["error"]
        if isinstance(error, dict):
            return {
                "available": False,
                "error_status": error.get("status"),
                "error_exit_code": error.get("exit_code"),
                "error_stderr_tail": error.get("stderr_tail"),
            }
        return {"available": False, "error": error}

    artifacts: dict[str, dict[str, Any]] = {}
    present: list[str] = []
    artifact_bytes = 0
    for name, exists_key, bytes_key in CACHE_ARTIFACTS:
        exists = bool(stats.get(exists_key))
        size = int_value(stats.get(bytes_key))
        artifacts[name] = {"exists": exists, "bytes": size}
        if exists:
            present.append(name)
            artifact_bytes += size

    return {
        "available": True,
        "bonsai_dir_exists": bool(stats.get("bonsai_dir_exists")),
        "total_bytes": int_value(stats.get("total_bytes")),
        "artifact_bytes": artifact_bytes,
        "present_artifacts": present,
        "artifacts": artifacts,
    }


def measured_step_by_label(steps: list[dict[str, Any]], prefix: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for step in steps:
        label = step.get("label")
        if not isinstance(label, str) or not label.startswith(prefix):
            continue
        if step.get("status") != "ok" or step.get("exit_code") != 0:
            continue
        out[label.removeprefix(prefix)] = step
    return out


def summarize_warm_speedups(
    cold_steps: list[dict[str, Any]],
    warm_steps: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    cold = measured_step_by_label(cold_steps, "cold_")
    warm = measured_step_by_label(warm_steps, "warm_")
    comparisons = {
        "index": "index",
        "callgraph": "callgraph",
        "export_all": "export_all_repeat",
        "source_analysis": "source_analysis",
        "taint_analysis": "taint_analysis",
    }
    out: dict[str, dict[str, Any]] = {}
    for cold_key, warm_key in comparisons.items():
        cold_step = cold.get(cold_key)
        warm_step = warm.get(warm_key)
        if cold_step is None or warm_step is None:
            continue
        cold_ms = cold_step.get("wall_ms")
        warm_ms = warm_step.get("wall_ms")
        if not isinstance(cold_ms, (int, float)) or not isinstance(warm_ms, (int, float)):
            continue
        ratio = round(cold_ms / warm_ms, 3) if warm_ms > 0 else None
        out[cold_key] = {
            "cold_wall_ms": cold_ms,
            "warm_wall_ms": warm_ms,
            "warm_vs_cold_ratio": ratio,
            "warm_delta_ms": round(warm_ms - cold_ms, 2),
            "cold_max_rss_bytes": cold_step.get("max_rss_bytes"),
            "warm_max_rss_bytes": warm_step.get("max_rss_bytes"),
        }
    return out


def summarize_export_phases(phases: dict[str, Any]) -> dict[str, Any]:
    flow = phases.get("flow sections") if isinstance(phases.get("flow sections"), dict) else {}
    chains = phases.get("taint.chains") if isinstance(phases.get("taint.chains"), dict) else {}
    labels = (
        phases.get("taint.flow_id_labels")
        if isinstance(phases.get("taint.flow_id_labels"), dict)
        else {}
    )
    propagations = (
        phases.get("taint.propagations")
        if isinstance(phases.get("taint.propagations"), dict)
        else {}
    )
    summary: dict[str, Any] = {
        "flow_chains_truncated_targets": int_value(flow.get("truncated_targets")),
        "taint_chains_truncated_targets": int_value(chains.get("truncated_targets")),
        "flow_id_labels_truncated_functions": int_value(labels.get("truncated_functions")),
        "phase_coverage_complete": bool(flow) and bool(chains) and bool(labels) and "complete" in propagations,
    }
    if "mode" in flow:
        summary["flow_chains_mode"] = flow["mode"]
    if "mode" in chains:
        summary["taint_chains_mode"] = chains["mode"]
    if "mode" in labels:
        summary["flow_id_labels_mode"] = labels["mode"]
    if "complete" in propagations:
        summary["propagations_complete"] = propagations["complete"]
    completeness_inputs = [
        summary["flow_chains_truncated_targets"] == 0,
        summary["taint_chains_truncated_targets"] == 0,
        summary["flow_id_labels_truncated_functions"] == 0,
    ]
    if "propagations_complete" in summary:
        completeness_inputs.append(summary["propagations_complete"] is True)
    summary["analysis_complete_from_phases"] = summary["phase_coverage_complete"] and all(completeness_inputs)
    return summary


def parse_export_phases(stderr: str) -> dict[str, Any]:
    phases: dict[str, Any] = {}
    for line in stderr.splitlines():
        match = EXPORT_PHASE_RE.match(line)
        if not match:
            continue
        name, seconds, rest = match.groups()
        phase: dict[str, Any] = {"seconds": float(seconds)}
        if rest:
            for token in rest.split():
                if "=" not in token:
                    continue
                key, value = token.split("=", 1)
                phase[key] = parse_scalar(value)
        phases[name] = phase
    return phases


def with_debug_category(env: dict[str, str], category: str) -> dict[str, str]:
    existing = env.get("BONSAI_DEBUG", "")
    enabled = [part.strip() for part in existing.split(",") if part.strip()]
    if "*" in enabled or category in enabled:
        return env
    enabled.append(category)
    env["BONSAI_DEBUG"] = ",".join(enabled)
    return env


def tail_text(path: Path, max_bytes: int) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > max_bytes:
                handle.seek(size - max_bytes)
            return handle.read(max_bytes).decode("utf-8", errors="replace")
    except OSError:
        return ""


def run_measured(
    *,
    binary: Path,
    root: Path,
    args: list[str],
    label: str,
    timer: list[str] | None,
    timeout_sec: float | None,
    rss_limit_bytes: int | None,
    parse_json: bool = False,
    store_json: bool = False,
    discard_stdout: bool = False,
) -> dict[str, Any]:
    stdout_path: Path | None = None
    if not discard_stdout:
        with tempfile.NamedTemporaryFile("w+b", delete=False) as stdout_file:
            stdout_path = Path(stdout_file.name)
    with tempfile.NamedTemporaryFile("w+b", delete=False) as stderr_file:
        stderr_path = Path(stderr_file.name)
    command = [str(binary), *args, "--no-color", "--no-progress"]
    full_command = [*timer, *command] if timer else command
    env = os.environ.copy()
    if args and args[0] == "export":
        env = with_debug_category(env, "export-phase")
    started = time.perf_counter()
    status = "ok"
    sampled_peak_rss: int | None = None
    proc: subprocess.Popen[bytes] | None = None
    try:
        stdout_handle = open(os.devnull, "wb") if discard_stdout else stdout_path.open("wb")  # type: ignore[union-attr]
        with stdout_handle as out, stderr_path.open("wb") as err:
            proc = subprocess.Popen(
                full_command,
                cwd=root,
                stdout=out,
                stderr=err,
                start_new_session=True,
                env=env,
            )
            while proc.poll() is None:
                elapsed = time.perf_counter() - started
                current_rss = process_tree_rss_bytes(proc.pid)
                if current_rss is not None:
                    sampled_peak_rss = max(sampled_peak_rss or 0, current_rss)
                if timeout_sec is not None and elapsed > timeout_sec:
                    status = "timeout"
                    terminate_process_group(proc)
                    break
                if (
                    rss_limit_bytes is not None
                    and current_rss is not None
                    and current_rss > rss_limit_bytes
                ):
                    status = "rss_limit"
                    terminate_process_group(proc)
                    break
                time.sleep(0.25)
            if status == "ok":
                proc.wait()
            else:
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    kill_process_group(proc)
                    proc.wait()
    finally:
        wall_ms = round((time.perf_counter() - started) * 1000, 2)
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    parsed = json_from_file(stdout_path) if parse_json and stdout_path is not None else None
    measured_rss = parse_rss_bytes(stderr_text)
    result: dict[str, Any] = {
        "label": label,
        "command": command,
        "exit_code": proc.returncode if proc is not None else None,
        "status": status,
        "wall_ms": wall_ms,
        "max_rss_bytes": max(
            value for value in (measured_rss, sampled_peak_rss) if value is not None
        )
        if measured_rss is not None or sampled_peak_rss is not None
        else None,
    }
    if stdout_path is not None:
        try:
            result["stdout_bytes"] = stdout_path.stat().st_size
        except OSError:
            pass
    export_phases = parse_export_phases(stderr_text)
    if export_phases:
        result["export_phases"] = export_phases
        result["export_phase_summary"] = summarize_export_phases(export_phases)
    if timeout_sec is not None:
        result["timeout_sec"] = timeout_sec
    if rss_limit_bytes is not None:
        result["rss_limit_bytes"] = rss_limit_bytes
    if parsed is not None:
        result["json_summary"] = summarize_json(parsed)
        if store_json:
            result["json"] = parsed
        if (rows := count_json_rows(parsed)) is not None:
            result["row_count"] = rows
    if result["exit_code"] != 0 or status != "ok":
        if stdout_path is not None:
            result["stdout_tail"] = tail_text(stdout_path, 2000)
        result["stderr_tail"] = stderr_text[-2000:]
    if stdout_path is not None:
        stdout_path.unlink(missing_ok=True)
    stderr_path.unlink(missing_ok=True)
    return result


def child_pids(pid: int) -> list[int]:
    try:
        proc = subprocess.run(
            ["pgrep", "-P", str(pid)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError:
        return []
    children = [int(raw) for raw in proc.stdout.split() if raw.isdigit()]
    out = children[:]
    for child in children:
        out.extend(child_pids(child))
    return out


def process_tree_rss_bytes(pid: int) -> int | None:
    pids = [pid, *child_pids(pid)]
    if not pids:
        return None
    try:
        proc = subprocess.run(
            ["ps", "-o", "rss=", "-p", ",".join(str(p) for p in pids)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError:
        return None
    total_kb = 0
    saw_value = False
    for raw in proc.stdout.split():
        try:
            total_kb += int(raw)
            saw_value = True
        except ValueError:
            continue
    return total_kb * 1024 if saw_value else None


def terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return


def kill_process_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def cache_stats(binary: Path, root: Path, workspace: Path, timer: list[str] | None) -> dict[str, Any]:
    result = run_measured(
        binary=binary,
        root=root,
        args=["cache", "stats", str(workspace), "--format", "json"],
        label="cache_stats",
        timer=timer,
        timeout_sec=60,
        rss_limit_bytes=None,
        parse_json=True,
        store_json=True,
    )
    return result.get("json", {}) if result["exit_code"] == 0 else {"error": result}


def run_checked(
    binary: Path,
    root: Path,
    workspace: Path,
    args: list[str],
    timer: list[str] | None,
    timeout_sec: float | None,
    rss_limit_bytes: int | None,
) -> dict[str, Any]:
    return run_measured(
        binary=binary,
        root=root,
        args=args,
        label=" ".join(args[:3]),
        timer=timer,
        timeout_sec=timeout_sec,
        rss_limit_bytes=rss_limit_bytes,
        parse_json=args.count("--format") > 0 and "json" in args,
    )


def clear_all(binary: Path, root: Path, workspace: Path, timer: list[str] | None) -> dict[str, Any]:
    return run_measured(
        binary=binary,
        root=root,
        args=["cache", "clear", str(workspace)],
        label="cache_clear_all",
        timer=timer,
        timeout_sec=60,
        rss_limit_bytes=None,
    )


def security_profile_args(target: Target) -> list[str]:
    # The production profile intentionally excludes examples, samples,
    # fixtures, tests, and demos. `examples/` is the primary regression
    # target for this project, so benchmarking it with the production
    # profile would measure an empty security scope.
    if target.name == "examples" and target.path.name == "examples":
        return []
    return ["--profile", "production"]


def bench_target(
    *,
    binary: Path,
    root: Path,
    source_target: Target,
    copy_mode: bool,
    runs: int,
    timer: list[str] | None,
    timeout_sec: float | None,
    rss_limit_bytes: int | None,
) -> dict[str, Any]:
    temp: tempfile.TemporaryDirectory[str] | None = None
    workspace = source_target.path
    if copy_mode:
        workspace, temp = copy_workspace(source_target.path, source_target.name)
    try:
        profile_args = security_profile_args(source_target)
        report: dict[str, Any] = {
            "name": source_target.name,
            "source_path": str(source_target.path),
            "workspace_path": str(workspace),
            "copied_workspace": copy_mode,
            "security_profile_args": profile_args,
            "runs": [],
        }
        for run_idx in range(runs):
            run: dict[str, Any] = {"run": run_idx + 1}
            run["initial_cache"] = cache_stats(binary, root, workspace, timer)

            cold: list[dict[str, Any]] = []
            for label, args, parse_json in (
                ("cold_index", ["index", str(workspace)], True),
                ("cold_callgraph", ["dump-callgraph", str(workspace), "--format", "json", "--all"], True),
                ("cold_export_all", ["export", str(workspace), "--format", "json", "--all"], False),
                (
                    "cold_source_analysis",
                    [
                        "security",
                        str(workspace),
                        "source-analysis",
                        *profile_args,
                        "--format",
                        "json",
                        "--all",
                    ],
                    True,
                ),
                (
                    "cold_taint_analysis",
                    [
                        "security",
                        str(workspace),
                        "taint-analysis",
                        *profile_args,
                        "--format",
                        "json",
                        "--all",
                    ],
                    True,
                ),
            ):
                cold.append(clear_all(binary, root, workspace, timer))
                cold.append(
                    run_measured(
                        binary=binary,
                        root=root,
                        args=args,
                        label=label,
                        timer=timer,
                        timeout_sec=timeout_sec,
                        rss_limit_bytes=rss_limit_bytes,
                        parse_json=parse_json,
                        discard_stdout=label == "cold_export_all",
                    )
                )
            run["cold"] = cold

            run["warm_setup_clear"] = clear_all(binary, root, workspace, timer)
            run["warm_setup"] = run_checked(
                binary,
                root,
                workspace,
                ["cache", "rebuild", str(workspace)],
                timer,
                timeout_sec,
                rss_limit_bytes,
            )
            run["warm_cache"] = cache_stats(binary, root, workspace, timer)
            run["warm"] = [
                run_measured(
                    binary=binary,
                    root=root,
                    args=["index", str(workspace)],
                    label="warm_index",
                    timer=timer,
                    timeout_sec=timeout_sec,
                    rss_limit_bytes=rss_limit_bytes,
                    parse_json=True,
                ),
                run_measured(
                    binary=binary,
                    root=root,
                    args=["export", str(workspace), "--format", "json", "--all"],
                    label="warm_export_all_build",
                    timer=timer,
                    timeout_sec=timeout_sec,
                    rss_limit_bytes=rss_limit_bytes,
                    parse_json=False,
                    discard_stdout=True,
                ),
                run_measured(
                    binary=binary,
                    root=root,
                    args=["export", str(workspace), "--format", "json", "--all"],
                    label="warm_export_all_repeat",
                    timer=timer,
                    timeout_sec=timeout_sec,
                    rss_limit_bytes=rss_limit_bytes,
                    parse_json=False,
                    discard_stdout=True,
                ),
                run_measured(
                    binary=binary,
                    root=root,
                    args=["dump-callgraph", str(workspace), "--format", "json", "--all"],
                    label="warm_callgraph",
                    timer=timer,
                    timeout_sec=timeout_sec,
                    rss_limit_bytes=rss_limit_bytes,
                    parse_json=True,
                ),
                run_measured(
                    binary=binary,
                    root=root,
                    args=[
                        "security",
                        str(workspace),
                        "source-analysis",
                        *profile_args,
                        "--format",
                        "json",
                        "--all",
                    ],
                    label="warm_source_analysis",
                    timer=timer,
                    timeout_sec=timeout_sec,
                    rss_limit_bytes=rss_limit_bytes,
                    parse_json=True,
                ),
                run_measured(
                    binary=binary,
                    root=root,
                    args=[
                        "security",
                        str(workspace),
                        "taint-analysis",
                        *profile_args,
                        "--format",
                        "json",
                        "--all",
                    ],
                    label="warm_taint_analysis",
                    timer=timer,
                    timeout_sec=timeout_sec,
                    rss_limit_bytes=rss_limit_bytes,
                    parse_json=True,
                ),
            ]
            run["final_cache"] = cache_stats(binary, root, workspace, timer)
            run["cache_summary"] = {
                "initial": summarize_cache_stats(run["initial_cache"]),
                "warm": summarize_cache_stats(run["warm_cache"]),
                "final": summarize_cache_stats(run["final_cache"]),
            }
            run["warm_speedups"] = summarize_warm_speedups(cold, run["warm"])
            report["runs"].append(run)
        return report
    finally:
        if temp is not None:
            temp.cleanup()


def validate_targets(targets: list[Target]) -> list[Target]:
    valid: list[Target] = []
    for target in targets:
        if not target.path.exists():
            print(f"warning: skipping missing target {target.name}={target.path}", file=sys.stderr)
            continue
        if not target.path.is_dir():
            print(f"warning: skipping non-directory target {target.name}={target.path}", file=sys.stderr)
            continue
        valid.append(target)
    return valid


def failed_measured_steps(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        failures: list[dict[str, Any]] = []
        if "exit_code" in value and "status" in value:
            if value.get("exit_code") not in (None, 0) or value.get("status") != "ok":
                failures.append(value)
        for nested in value.values():
            failures.extend(failed_measured_steps(nested))
        return failures
    if isinstance(value, list):
        failures: list[dict[str, Any]] = []
        for nested in value:
            failures.extend(failed_measured_steps(nested))
        return failures
    return []


def main() -> int:
    root = repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", help="bonsai-ninja binary path; defaults to release then debug")
    parser.add_argument("--target", action="append", type=parse_target, help="Benchmark target as name=path")
    parser.add_argument("--runs", type=int, default=1, help="Number of cold/warm repetitions per target")
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Benchmark the real target directory. Default benchmarks a temp copy and deletes only that copy's .bonsai.",
    )
    parser.add_argument(
        "--discover-large",
        action="store_true",
        help="Search nearby directories for Redis and OWASP Benchmark targets and include any found.",
    )
    parser.add_argument("--output", type=Path, help="Write JSON report to this path")
    parser.add_argument(
        "--timeout-sec",
        type=float,
        default=300.0,
        help="Per-command wall-time guard. Use 0 to disable.",
    )
    parser.add_argument(
        "--rss-limit-mb",
        type=int,
        default=2048,
        help="Per-command process-tree RSS guard. Use 0 to disable.",
    )
    args = parser.parse_args()

    if args.runs < 1:
        raise SystemExit("--runs must be >= 1")

    binary = find_binary(root, args.binary)
    targets = args.target or default_targets(root)
    if args.discover_large:
        known = {(target.name, target.path) for target in targets}
        for target in discover_large_targets(root):
            if (target.name, target.path) not in known:
                targets.append(target)
                known.add((target.name, target.path))
    targets = validate_targets(targets)
    if not targets:
        raise SystemExit("no benchmark targets to run")

    timer = time_style()
    timeout_sec = None if args.timeout_sec == 0 else args.timeout_sec
    rss_limit_bytes = None if args.rss_limit_mb == 0 else args.rss_limit_mb * 1024 * 1024
    report: dict[str, Any] = {
        "schema": "bonsai.goal-benchmark.v1",
        "repo": str(root),
        "binary": str(binary),
        "timer": timer,
        "timeout_sec": timeout_sec,
        "rss_limit_bytes": rss_limit_bytes,
        "generated_unix_ms": int(time.time() * 1000),
        "targets": [],
    }
    for target in targets:
        report["targets"].append(
            bench_target(
                binary=binary,
                root=root,
                source_target=target,
                copy_mode=not args.in_place,
                runs=args.runs,
                timer=timer,
                timeout_sec=timeout_sec,
                rss_limit_bytes=rss_limit_bytes,
            )
        )

    encoded = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    else:
        print(encoded)

    failed = failed_measured_steps(report["targets"])
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
