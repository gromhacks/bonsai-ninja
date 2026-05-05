"""Sink layer.

`CommandRunner.execute` is where the long chain terminates.
`os.system(cmd)` is the canonical rulepack command-injection sink
(`python.cmdi.os_system`, severity: critical, CWE-78). The class also
implements `__call__` so the same runner instance is callable directly
— both paths end at the same sink.
"""

from __future__ import annotations

import os


class CommandRunner:
    """Callable object. `__call__` and `execute` both reach `os.system`."""

    def __init__(self) -> None:
        self.history: list[str] = []

    def __call__(self, cmd: str) -> int:
        # Callable-object path — same sink at the other end.
        return self.execute(cmd)

    def execute(self, cmd: str) -> int:
        """SINK — os.system with attacker-controlled cmd."""
        self.history.append(cmd)
        # python.cmdi.os_system · severity=critical · CWE-78
        return os.system(cmd)


def clean_twin() -> int:
    """NEGATIVE — same sink kind with a constant argument must not report."""
    return os.system("echo clean")
