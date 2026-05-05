"""Async pipeline orchestrator.

`orchestrate` awaits an async generator (`stream_batch`), validates each
chunk, persists the valid payload through `storage.Repository`, and
catches the ValueError raised for invalid payloads. The tainted
`cmd` string rides the dict through every hop.
"""

from __future__ import annotations

from typing import Any, AsyncIterator

from transformers import batch_expand, normalize
from validators import validate_payload


async def orchestrate(envelope: dict[str, Any]) -> tuple[bool, Any]:
    """Top-level coroutine. Async-iterates, validates, persists."""
    last_out: Any = None
    try:
        # async-for over an async generator — taint flows through
        # the yielded `chunk` dicts.
        async for chunk in stream_batch(envelope):
            chunk = await _identity(chunk)
            valid = validate_payload(chunk)

            # Late import breaks what would otherwise be a module
            # cycle (`storage` imports from `executor`, `executor`
            # has no back-edge but we still want the analyzer to
            # trace through a late binding).
            from storage import AuditedRepository

            repo = AuditedRepository(valid, who=envelope.get("user", "anon"))
            last_out = repo.persist()
        return True, last_out
    except ValueError as e:
        # Exception args carry the tainted payload string.
        return False, str(e)


async def stream_batch(envelope: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
    """Async generator. Each yield is a tainted chunk bound for a sink."""
    # Subscript + .get with default — both land `cmd` back on the
    # taint graph.
    cmd: str = envelope["cmd"]
    user: str = envelope.get("user", "anon")

    # map + lambda over split parts, then filter via list comp.
    parts = list(map(lambda s: s.strip(), cmd.split(" ")))
    parts = [p for p in parts if p]

    # Dict comprehension — rebuild the context without `cmd`.
    ctx = {k: envelope[k] for k in envelope if k != "cmd"}

    # The rejoined string lives in `parts` elements. `batch_expand`
    # re-wraps each element into a dict with the rest of `ctx`.
    for expanded in batch_expand(parts, ctx):
        normalized = normalize(expanded, user=user)
        yield normalized  # async generator yield


async def _identity(chunk: dict[str, Any]) -> dict[str, Any]:
    return chunk
