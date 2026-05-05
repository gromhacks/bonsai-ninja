"""Transformer helpers — comprehensions, match/case, reduce, yield-from.

`batch_expand` is a generator that wraps each tainted `part` into a
dict with surrounding context. `normalize` reduces parts back into a
single tainted string stored under `value` in the output dict.
"""

from __future__ import annotations

from functools import reduce
from typing import Any, Iterator


def batch_expand(parts: list[str], ctx: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Generator — yields one dict per `part` with match/case shaping."""
    for i, p in enumerate(parts):
        # match/case over a string value. Each branch yields a
        # different shape, all carrying the tainted `p`.
        match p:
            case "":
                continue
            case p if p.startswith("--"):
                yield {"flag": p, **ctx}
            case _:
                yield {"arg": p, "index": i, **ctx}

    # yield from — chain a second generator so the analyzer sees a
    # `yield from` edge too.
    yield from _trailer_marker(ctx)


def _trailer_marker(ctx: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """One-shot generator for yield-from coverage."""
    yield {"arg": "__end__", **ctx}


def normalize(item: dict[str, Any], user: str = "anon") -> dict[str, Any]:
    """Walrus + reduce + lambda + f-string + ternary — rebuild the cmd."""
    # Walrus inside a comprehension — captures each non-None value.
    keys = [k for k in item if (v := item.get(k)) is not None]

    # Ternary — flag vs arg determines `tag`.
    tag = "flag" if "flag" in item else "arg"
    payload = item.get("flag") or item.get("arg") or ""

    # reduce + lambda — folds the single-element list back into a
    # stripped string. The tainted `payload` rides through the
    # closure in the lambda.
    joined = reduce(lambda a, b: f"{a} {b}", [payload], "")

    # .format — another way the tainted string becomes a larger one.
    footer = "user={u}".format(u=user)

    # %-format — third formatter shape; keeps `payload` in the value.
    mark = "[%s]" % tag

    return {
        "user": user,
        "tag": tag,
        "value": joined.strip(),   # ← tainted (still carries `cmd`)
        "keys": keys,
        "footer": footer,
        "mark": mark,
    }
