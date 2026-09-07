"""Python sanitizer-fixture — two parallel handlers per sink family.

Each family has:
  - `<name>_raw(req)`     source → sink directly (SHOULD FLAG).
  - `<name>_safe(req)`    historical name for the transformed/control leg.

html.escape credits HTML output. Shell/URL quoting alone does not prove
the execution or destination context. A fixed local redirect prefix is
safe independently of URL encoding; IDG propagation is never removed.
"""

from __future__ import annotations

import html
import os
import shlex
from urllib.parse import quote

from flask import Flask, request

app = Flask(__name__)


# --- Command injection ------------------------------------------------------

@app.route("/cmd/raw")
def cmd_raw():
    # SOURCE → SINK directly — expected finding.
    cmd = request.args.get("cmd", "")
    return os.system("ping " + cmd)


@app.route("/cmd/safe")
def cmd_safe():
    # Quoting remains a transform without a proven interpreter/argument context.
    cmd = request.args.get("cmd", "")
    safe = shlex.quote(cmd)
    return os.system("ping " + safe)


# --- XSS --------------------------------------------------------------------

@app.route("/xss/raw")
def xss_raw():
    # SOURCE → response body (SINK).
    name = request.args.get("name", "")
    return f"<p>Hello, {name}</p>"  # tainted HTML


@app.route("/xss/safe")
def xss_safe():
    name = request.args.get("name", "")
    safe = html.escape(name)
    return f"<p>Hello, {safe}</p>"


# --- Open redirect ----------------------------------------------------------

@app.route("/redirect/raw")
def redirect_raw():
    from flask import redirect
    target = request.args.get("to", "")
    return redirect(target)


@app.route("/redirect/safe")
def redirect_safe():
    from flask import redirect
    target = request.args.get("to", "")
    safe = quote(target, safe="")
    return redirect("/next?to=" + safe)
