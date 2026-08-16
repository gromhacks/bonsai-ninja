#!/usr/bin/env python3
"""Verify documented CLI commands and flags against the release binary."""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
DOCUMENTS = (
    REPO / "README.md",
    REPO / "CONTRIBUTING.md",
    REPO / "SECURITY.md",
    REPO / "AGENTS.md",
    REPO / "SKILLS.md",
    REPO / ".github" / "PULL_REQUEST_TEMPLATE.md",
)
FLAG_TOKEN = re.compile(r"^--[a-z][a-z0-9-]*$")
FENCE = re.compile(r"^\s*(?:`{3,}|~{3,})")
BACKTICK_RUN = re.compile(r"(?<!\\)(`+)")


def documentation_files() -> list[Path]:
    files = list(DOCUMENTS)
    files.extend((REPO / "docs").rglob("*.md"))
    files.extend((REPO / "docs").rglob("*.mdx"))
    files.extend((REPO / ".agents").rglob("*.md"))
    return sorted({path for path in files if path.is_file()})


def logical_lines(path: Path) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    pending = ""
    start = 0
    inline_delimiter: str | None = None
    for number, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
        stripped = raw.strip()
        # Fenced blocks already preserve command boundaries line-by-line. Treating
        # their fence markers as inline delimiters would merge the entire block
        # into one invocation.
        if not pending and FENCE.match(raw):
            rows.append((number, stripped))
            continue
        if not pending:
            start = number
        pending = f"{pending} {stripped}".strip()

        # Markdown permits an inline code span to wrap across source lines. Join
        # those lines before tokenizing so a wrapped Cargo command cannot make a
        # dependency package name look like a standalone bonsai-ninja command.
        for match in BACKTICK_RUN.finditer(raw):
            delimiter = match.group(1)
            if inline_delimiter is None:
                inline_delimiter = delimiter
            elif delimiter == inline_delimiter:
                inline_delimiter = None

        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        if inline_delimiter is not None:
            continue
        rows.append((start, pending))
        pending = ""
    if pending:
        rows.append((start, pending))
    return rows


def invocation_tokens(line: str) -> list[str] | None:
    normalized = line.replace("`", "")
    try:
        tokens = shlex.split(normalized, comments=True)
    except ValueError:
        return None
    for index, token in enumerate(tokens):
        candidate = token.lstrip("$>")
        executable_prefix = [
            prior
            for prior in tokens[:index]
            if prior not in {"$", ">"} and "=" not in prior
        ]
        if (
            not executable_prefix
            and not candidate.startswith("-")
            and Path(candidate).name
            in {
                "bonsai-ninja",
                "bonsai-ninja.exe",
            }
        ):
            return [candidate, *tokens[index + 1 :]]
    return None


def help_output(binary: Path, args: list[str]) -> tuple[str, str | None]:
    completed = subprocess.run(
        [str(binary), *args, "--help"],
        cwd=REPO,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode != 0:
        return completed.stdout, f"help exited {completed.returncode}"
    return completed.stdout, None


def command_help_args(tokens: list[str]) -> list[str]:
    if len(tokens) < 2 or tokens[1].startswith("-"):
        return []
    command = tokens[1].rstrip(".,:;)")
    if command == "security" and len(tokens) >= 4:
        workspace = tokens[2]
        action = tokens[3].rstrip(".,:;)")
        if not workspace.startswith("-") and not action.startswith("-"):
            return [command, workspace, action]
    if command == "cache" and len(tokens) >= 3:
        action = tokens[2].rstrip(".,:;)")
        if not action.startswith("-"):
            return [command, action]
    return [command]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        type=Path,
        default=REPO / "target" / "release" / "bonsai-ninja",
    )
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"release binary not found: {binary}")

    root_help, root_error = help_output(binary, [])
    if root_error:
        print(f"CLI documentation audit: root {root_error}")
        return 1

    failures: list[str] = []
    checked = 0
    help_cache: dict[tuple[str, ...], str] = {(): root_help}
    command_index = root_help.split("COMMAND GROUPS", 1)[1].split("OPTIONS", 1)[0]
    command_rows = re.findall(
        r"^\s{4}([a-z][a-z-]*(?: [a-z][a-z-]*)?)\s{2,}",
        command_index,
        re.MULTILINE,
    )
    for command_row in command_rows:
        parts = command_row.split()
        help_args = ["security", ".", parts[1]] if parts[0] == "security" else parts
        key = tuple(help_args)
        output, error = help_output(binary, help_args)
        if error:
            failures.append(
                f"root command index contains invalid help path "
                f"`{' '.join(help_args)}` ({error})"
            )
        else:
            help_cache[key] = output

    for path in documentation_files():
        for line_number, line in logical_lines(path):
            tokens = invocation_tokens(line)
            if tokens is None:
                continue
            help_args = command_help_args(tokens)
            key = tuple(help_args)
            if key not in help_cache:
                output, error = help_output(binary, help_args)
                if error:
                    failures.append(
                        f"{path.relative_to(REPO)}:{line_number}: "
                        f"`{' '.join(help_args)}` is not a valid help path ({error})"
                    )
                    continue
                help_cache[key] = output

            accepted_help = root_help + "\n" + help_cache[key]
            for token in tokens[1:]:
                flag = token.rstrip("`.,:;)")
                if FLAG_TOKEN.fullmatch(flag) and flag not in accepted_help:
                    failures.append(
                        f"{path.relative_to(REPO)}:{line_number}: `{flag}` is not "
                        f"documented by `bonsai-ninja {' '.join(help_args)} --help`"
                    )
            checked += 1

    cli_reference = (REPO / "docs" / "cli-reference.mdx").read_text(errors="replace")
    referenced_flags = set(re.findall(r"`(--[a-z][a-z0-9-]*)", cli_reference))
    documented_help = "\n".join(help_cache.values())
    for flag in sorted(referenced_flags):
        if flag not in documented_help:
            failures.append(
                f"docs/cli-reference.mdx: `{flag}` is not present in any "
                "documented command's binary help"
            )

    if failures:
        for failure in failures:
            print(f"CLI documentation audit: {failure}")
        return 1
    print(
        f"CLI documentation audit: {checked} invocations and "
        f"{len(referenced_flags)} reference flags across "
        f"{len(documentation_files())} files match {len(command_rows)} binary help surfaces"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
