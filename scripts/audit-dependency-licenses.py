#!/usr/bin/env python3
"""Fail when the locked Cargo graph has missing or unreviewed licenses."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass


ALLOWED = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "CDLA-Permissive-2.0",
    "ISC",
    "MIT",
    "MPL-2.0",
    "Unicode-3.0",
    "Unlicense",
    "Zlib",
}
REVIEWED_DENIED = {
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "EUPL-1.2",
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "SSPL-1.0",
}
TOKEN = re.compile(r"\s*(\(|\)|AND\b|OR\b|WITH\b|[A-Za-z0-9.+-]+)")


@dataclass(frozen=True)
class Verdict:
    satisfiable: bool
    unknown: frozenset[str] = frozenset()

    def and_(self, other: "Verdict") -> "Verdict":
        return Verdict(self.satisfiable and other.satisfiable, self.unknown | other.unknown)

    def or_(self, other: "Verdict") -> "Verdict":
        return Verdict(self.satisfiable or other.satisfiable, self.unknown | other.unknown)


class Parser:
    def __init__(self, expression: str) -> None:
        normalized = expression.replace("/", " OR ")
        self.tokens = TOKEN.findall(normalized)
        compact = "".join(self.tokens).replace("AND", "").replace("OR", "").replace("WITH", "")
        expected = re.sub(r"[\s/]", "", expression).replace("AND", "").replace("OR", "").replace("WITH", "")
        if compact != expected:
            raise ValueError(f"unsupported SPDX syntax: {expression!r}")
        self.index = 0

    def parse(self) -> Verdict:
        verdict = self.parse_or()
        if self.index != len(self.tokens):
            raise ValueError(f"unexpected token {self.tokens[self.index]!r}")
        return verdict

    def parse_or(self) -> Verdict:
        verdict = self.parse_and()
        while self.peek() == "OR":
            self.index += 1
            verdict = verdict.or_(self.parse_and())
        return verdict

    def parse_and(self) -> Verdict:
        verdict = self.parse_primary()
        while self.peek() == "AND":
            self.index += 1
            verdict = verdict.and_(self.parse_primary())
        return verdict

    def parse_primary(self) -> Verdict:
        token = self.peek()
        if token == "(":
            self.index += 1
            verdict = self.parse_or()
            self.expect(")")
            return verdict
        if token is None or token in {"AND", "OR", "WITH", ")"}:
            raise ValueError(f"expected license id, got {token!r}")
        self.index += 1
        if self.peek() == "WITH":
            self.index += 1
            exception = self.peek()
            if exception is None:
                raise ValueError("missing SPDX exception after WITH")
            self.index += 1
            combined = f"{token} WITH {exception}"
            if combined == "Apache-2.0 WITH LLVM-exception":
                return Verdict(True)
            return Verdict(False, frozenset({combined}))
        if token in ALLOWED:
            return Verdict(True)
        if token in REVIEWED_DENIED:
            return Verdict(False)
        return Verdict(False, frozenset({token}))

    def peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def expect(self, expected: str) -> None:
        if self.peek() != expected:
            raise ValueError(f"expected {expected!r}, got {self.peek()!r}")
        self.index += 1


def expression_verdict(expression: str) -> Verdict:
    return Parser(expression).parse()


def self_test() -> None:
    assert expression_verdict("MIT").satisfiable
    assert expression_verdict("MIT OR LGPL-2.1-or-later").satisfiable
    assert not expression_verdict("MIT AND LGPL-2.1-or-later").satisfiable
    assert expression_verdict("Apache-2.0 WITH LLVM-exception").satisfiable
    unknown = expression_verdict("LicenseRef-Future OR MIT")
    assert unknown.satisfiable and unknown.unknown == {"LicenseRef-Future"}


def main() -> int:
    self_test()
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            text=True,
        )
    )
    violations: list[str] = []
    licenses: Counter[str] = Counter()
    for package in sorted(metadata["packages"], key=lambda item: (item["name"], item["version"])):
        expression = package.get("license")
        if not expression:
            violations.append(f"{package['name']} {package['version']}: missing SPDX license expression")
            continue
        licenses[expression] += 1
        try:
            verdict = expression_verdict(expression)
        except ValueError as error:
            violations.append(f"{package['name']} {package['version']}: {error}")
            continue
        if verdict.unknown:
            violations.append(
                f"{package['name']} {package['version']}: unreviewed license id(s) "
                f"{', '.join(sorted(verdict.unknown))} in {expression!r}"
            )
        elif not verdict.satisfiable:
            violations.append(
                f"{package['name']} {package['version']}: no approved branch in {expression!r}"
            )
    if violations:
        print("dependency-license violations:", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1
    print(
        "dependency-licenses: 0 violations "
        f"({len(metadata['packages'])} locked packages, {len(licenses)} SPDX expressions)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
