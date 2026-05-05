"""Validator — match/case on dict shape, with a `raise` branch.

Returns `{"cmd": tainted_string, ...}` on success; raises a
`ValueError` whose message embeds the tainted input on failure (the
catcher in pipeline.orchestrate turns that back into a tainted
string in the HTTP response — exercises taint-through-exception).
"""

from __future__ import annotations

from typing import Any


def validate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Dict-shape pattern match. Returns `{"cmd": <tainted>, ...}`."""
    match payload:
        case {"tag": "flag", "value": v, **rest}:
            # Set-comprehension over the rest of the dict for coverage.
            leftover = {k for k in rest}
            return {"kind": "flag", "cmd": v, "leftover": leftover, **rest}
        case {"tag": "arg", "value": v, **rest}:
            return {"kind": "arg", "cmd": v, **rest}
        case _:
            # f-string embeds the tainted payload in the error message.
            raise ValueError(f"unknown payload: {payload}")
