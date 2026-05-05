"""mega_flow — entry point.

The Flask handler is the SOURCE. From here the tainted `cmd` string
traverses a decorator factory, an async pipeline, an async generator,
a cascade of comprehensions/match-cases/context managers, and finally
lands at `os.system` in `executor.py`.
"""

from __future__ import annotations

import asyncio
from typing import Any

from flask import Flask, jsonify, request

from middleware import auditable as audit_route
from pipeline import orchestrate as run_orchestrate

app = Flask(__name__)


@app.route("/run")
@audit_route("cmd-execution")  # decorator factory with aliased config arg
def handle_request():
    """Entry point. User-controlled HTTP query string enters here."""
    # SOURCE — Flask request.args.get is the rulepack's remote-trust
    # http-input source. The `cmd` parameter flows from this line all
    # the way through to `os.system` in executor.py.
    raw_cmd: str = request.args.get("cmd", "")
    mode: str = request.args.get("mode", "sync")
    user: str = request.headers.get("X-User", "anon")

    # Walrus + ternary — payload is None when there's nothing to run.
    payload = (
        {"cmd": raw_cmd, "user": user}
        if (n := len(raw_cmd)) > 0
        else None
    )
    if payload is None:
        return jsonify({"error": "empty"}), 400

    # Dict unpacking + augmented assignment — taint propagates through
    # the `**payload` spread into `envelope`.
    envelope: dict[str, Any] = {"kind": "run", **payload, "length": n}
    envelope["mode"] = mode

    # Multi-return / tuple unpacking — `result` is still tainted.
    ok, result = run_pipeline(envelope)
    return jsonify({"ok": ok, "result": result})


def run_pipeline(envelope: dict[str, Any]) -> tuple[bool, Any]:
    """Bridge from sync Flask handler into the async pipeline."""
    # asyncio.run wraps the top-level coroutine.
    return asyncio.run(run_orchestrate(envelope))
