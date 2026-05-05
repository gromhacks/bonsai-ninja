"""Decorator factory + contextlib context manager.

`auditable(tag)` is a three-level construct:
  outer factory  →  decorator  →  wrapper(*args, **kwargs)

Used at call sites as `@auditable("tag")` (or aliased: `audit_route as
auditable` in app.py — same decorator, different local name).

The wrapper forwards *args/**kwargs to `trace_calls` in utils.py,
which in turn forwards to the original handler — so the decorator
doesn't swallow the taint, it threads it through.
"""

from __future__ import annotations

import contextlib
import functools
from typing import Any, Callable

from utils import trace_calls


@contextlib.contextmanager
def audit_context(tag: str):
    """Context manager — `with audit_context("tag") as ctx: ...`."""
    ctx = {"tag": tag, "depth": 0}
    try:
        yield ctx
    finally:
        ctx["depth"] = -1  # no-op; kept to exercise `finally`


def auditable(tag: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory — returns a decorator that returns a wrapper."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Context manager wraps the call; taint threads through
            # *args unchanged.
            with audit_context(tag) as ctx:
                return trace_calls(fn, ctx, *args, **kwargs)

        return wrapper

    return decorator
