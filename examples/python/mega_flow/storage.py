"""Storage layer — class hierarchy + context manager + iterator protocol.

The validated, tainted dict enters here. `AuditedRepository` extends
`Repository`, calls `super().__init__`, exposes the data via
`@property`, uses `@classmethod` / `@staticmethod`, and its `persist()`
method opens a `Transaction` context manager that drives the sink.
"""

from __future__ import annotations

from typing import Any, Iterator

from executor import CommandRunner


class Transaction:
    """Class-based context manager. Also implements iter/next."""

    def __init__(self, runner: CommandRunner, tag: str):
        self.runner = runner
        self.tag = tag
        self.log: list[str] = []

    def __enter__(self) -> "Transaction":
        return self

    def __exit__(self, *a: Any) -> bool:
        return False  # don't swallow exceptions

    def __iter__(self) -> Iterator[str]:
        return iter(self.log)

    def __next__(self) -> str:
        return self.log.pop(0)

    def perform(self, cmd: str) -> int:
        """Forward `cmd` into the executor — last hop before the sink."""
        self.log.append(cmd)
        # Tainted `cmd` is the call argument — the analyzer should
        # follow this into CommandRunner.execute.
        return self.runner.execute(cmd)


class Repository:
    """Base class — __init__, @property, @classmethod, @staticmethod."""

    def __init__(self, data: dict[str, Any]):
        self._data = data

    @property
    def data(self) -> dict[str, Any]:
        return self._data

    @classmethod
    def _new_runner(cls) -> CommandRunner:
        # Classmethod — still produces the CommandRunner instance
        # that the tainted cmd is about to hit.
        return CommandRunner()

    @staticmethod
    def _build_tag(prefix: str) -> str:
        return f"{prefix}::tx"

    def persist(self) -> int:
        """Open a Transaction; call through to the sink."""
        runner = type(self)._new_runner()
        cmd = self.data["cmd"]  # ← tainted string lands here
        tag = Repository._build_tag("persist")
        with Transaction(runner, tag) as tx:
            return tx.perform(cmd)


class AuditedRepository(Repository):
    """Subclass — inherits persist(), adds super().__init__ + extra state."""

    def __init__(self, data: dict[str, Any], who: str = "anon"):
        super().__init__(data)
        self.who = who

    @property
    def data(self) -> dict[str, Any]:
        # Override the property but forward the field through.
        return self._data
