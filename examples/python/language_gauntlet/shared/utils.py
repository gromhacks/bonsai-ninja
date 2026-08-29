"""Shared helpers.

`trace_calls` sits between the decorator wrapper and the real handler,
exercising: nested functions (closure over `fn`/`ctx`), `functools.partial`,
`nonlocal`, and `*args`/`**kwargs` forwarding.
"""

from __future__ import annotations

import functools
from typing import Any, Callable


def trace_calls(fn: Callable[..., Any], ctx: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
    """Invoke `fn(*args, **kwargs)`, threading taint through unchanged."""
    counter = 0  # mutable state captured by `_hook`'s nonlocal.

    def _log() -> str:
        # Closure — captures both `fn` and `ctx` from the enclosing scope.
        return f"call={fn.__name__} tag={ctx.get('tag')}"

    def _hook() -> int:
        # Nested function with `nonlocal` — bumps the outer counter.
        nonlocal counter
        counter += 1
        return counter

    # functools.partial — another dispatch path that still calls `fn`
    # with the same (args, kwargs). The analyzer should see the call
    # even though it happens through a partial object.
    deferred = functools.partial(fn, *args, **kwargs)

    _ = _log()
    _ = _hook()
    # Preserve the taint path: the inner call is what carries the
    # tainted first positional arg forward.
    return deferred()
