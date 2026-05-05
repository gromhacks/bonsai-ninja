"""
Advanced data processing pipeline demonstrating taint flow through
Python's most challenging syntax features. Each vulnerability chain
exercises a distinct syntax pattern that static analysis must handle.
"""

import os
import asyncio
import sqlite3
import subprocess
import json
import functools
from contextlib import contextmanager
from flask import Flask, request, jsonify, render_template_string


app = Flask(__name__)
db_path = os.environ.get("DATABASE_URL", "pipeline.db")


# ============================================================
# Helpers
# ============================================================

def get_connection():
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# 1. Async/Await Chain
# VULN: request.args["cmd"] -> fetch_remote_config -> run_remote_task -> subprocess.run (command injection)
# ============================================================

async def fetch_remote_config(host):
    """Simulates fetching config from a remote host."""
    await asyncio.sleep(0)
    command = f"curl -s http://{host}/config"
    return command


async def run_remote_task(command):
    """Executes the fetched command string."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@app.route("/api/remote/config")
def trigger_remote_config():
    host = request.args["host"]
    loop = asyncio.new_event_loop()
    command = loop.run_until_complete(fetch_remote_config(host))
    output = loop.run_until_complete(run_remote_task(command))
    loop.close()
    return jsonify({"output": output})


# ============================================================
# 2. Generator / Yield
# VULN: request.args["filter"] -> stream_rows (generator) -> build_report_page -> render_template_string (XSS)
# ============================================================

def stream_rows(filter_expr):
    """Yields rows matching a user-supplied filter expression."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reports")
    for row in cursor.fetchall():
        if filter_expr in row["title"]:
            yield dict(row)
    conn.close()


def build_report_page(rows_iter):
    """Collects generator output into an HTML page."""
    parts = ["<h1>Report Results</h1><ul>"]
    for row in rows_iter:
        parts.append("<li>" + row["title"] + "</li>")
    parts.append("</ul>")
    return "".join(parts)


@app.route("/api/reports/stream")
def stream_reports():
    filter_text = request.args["filter"]
    rows = stream_rows(filter_text)
    html_page = build_report_page(rows)
    return render_template_string(html_page)


# ============================================================
# 3. Match/Case (Python 3.10+ Structural Pattern Matching)
# VULN: request.json["action"] -> dispatch_action (match/case) -> cursor.execute (SQL injection)
# ============================================================

def dispatch_action(action_payload):
    """Routes action through match/case, forwarding tainted data."""
    action_type = action_payload["type"]
    value = action_payload["value"]

    match action_type:
        case "query":
            return execute_custom_query(value)
        case "delete":
            return execute_custom_query(f"DELETE FROM records WHERE id = '{value}'")
        case "update":
            return execute_custom_query(f"UPDATE records SET status = 'done' WHERE name = '{value}'")
        case _:
            return {"error": "Unknown action"}


def execute_custom_query(sql):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(sql)
    conn.commit()
    results = cursor.fetchall()
    conn.close()
    return [dict(r) for r in results] if results else []


@app.route("/api/actions/dispatch", methods=["POST"])
def handle_action():
    payload = request.json
    result = dispatch_action(payload)
    return jsonify(result)


# ============================================================
# 4. Decorator Wrapping
# VULN: request.form["template"] -> render_with_log (decorator) -> inner render_template_string (template injection)
# ============================================================

def log_render(func):
    """Decorator that logs the rendered output and passes data through."""
    @functools.wraps(func)
    def wrapper(template_str, **kwargs):
        result = func(template_str, **kwargs)
        with open("/var/log/renders.log", "a") as f:
            f.write(f"Rendered: {template_str[:80]}\n")
        return result
    return wrapper


@log_render
def render_with_log(template_str, **kwargs):
    """Renders a user-supplied template after decorator wrapping."""
    return render_template_string(template_str, **kwargs)


@app.route("/api/templates/preview", methods=["POST"])
def preview_template():
    user_template = request.form["template"]
    username = request.form.get("username", "anonymous")
    output = render_with_log(user_template, user=username)
    return output


# ============================================================
# 5. List Comprehension -> SQL
# VULN: request.json["tags"] -> list comprehension build -> " OR ".join -> cursor.execute (SQL injection)
# ============================================================

def build_tag_query(tags):
    """Builds a SQL WHERE clause from a list of user-supplied tags."""
    conditions = ["tag = '" + t + "'" for t in tags]
    where_clause = " OR ".join(conditions)
    sql = "SELECT * FROM articles WHERE " + where_clause
    return sql


@app.route("/api/articles/by-tags", methods=["POST"])
def articles_by_tags():
    tags = request.json["tags"]
    sql = build_tag_query(tags)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(sql)
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(results)


# ============================================================
# 6. Walrus Operator (:=)
# VULN: request.args["q"] -> walrus assignment -> format_search_header -> render_template_string (XSS)
# ============================================================

def format_search_header(query_text):
    """Formats query text into an HTML header string."""
    return f"<h2>Search results for: {query_text}</h2>"


@app.route("/api/search/walrus")
def walrus_search():
    if (query := request.args.get("q")) is not None:
        header = format_search_header(query)
        body = "<p>Processing your search...</p>"
        page = header + body
        return render_template_string(page)
    return jsonify({"error": "Missing query parameter"}), 400


# ============================================================
# 7. Closure Capture
# VULN: request.form["expr"] -> make_evaluator (closure) -> eval (code injection)
# ============================================================

def make_evaluator(expression):
    """Returns a closure that captures the user-supplied expression."""
    def evaluate():
        return eval(expression)
    return evaluate


@app.route("/api/calc", methods=["POST"])
def calculator():
    expr = request.form["expr"]
    evaluator = make_evaluator(expr)
    result = evaluator()
    return jsonify({"result": str(result)})


# ============================================================
# 8. Context Manager
# VULN: request.json["filename"] -> managed_file (context manager) -> open (path traversal)
# ============================================================

@contextmanager
def managed_file(path, mode="r"):
    """Context manager that opens a file from a user-supplied path."""
    f = open(path, mode)
    try:
        yield f
    finally:
        f.close()


@app.route("/api/files/read", methods=["POST"])
def read_user_file():
    filename = request.json["filename"]
    base_dir = "/var/app/data"
    full_path = os.path.join(base_dir, filename)
    with managed_file(full_path) as f:
        content = f.read()
    return jsonify({"content": content})


# ============================================================
# 9. *args Forwarding
# VULN: request.json["command"] -> run_task(*args) -> execute_shell(*args) -> os.system (command injection)
# ============================================================

def execute_shell(*args):
    """Executes a shell command assembled from *args."""
    cmd = " ".join(args)
    os.system(cmd)
    return {"status": "executed"}


def run_task(program, *args):
    """Forwards arguments through *args to the shell executor."""
    return execute_shell(program, *args)


@app.route("/api/tasks/run", methods=["POST"])
def run_user_task():
    program = request.json["command"]
    arguments = request.json.get("args", [])
    result = run_task(program, *arguments)
    return jsonify(result)


# ============================================================
# 10. F-string Multi-Hop
# VULN: request.args["name"] -> greet -> build_welcome_email -> os.system via sendmail (command injection)
# ============================================================

def greet(name):
    """Formats a greeting using the user-supplied name."""
    return f"Hello, {name}!"


def build_welcome_email(greeting, recipient):
    """Builds a sendmail command string from formatted greeting."""
    subject = f"Welcome - {greeting}"
    cmd = f"sendmail -t {recipient} -s '{subject}'"
    return cmd


@app.route("/api/welcome")
def welcome_user():
    name = request.args["name"]
    email = request.args["email"]
    greeting = greet(name)
    mail_cmd = build_welcome_email(greeting, email)
    os.system(mail_cmd)
    return jsonify({"status": "welcome email sent"})


# ============================================================
# 11. Higher-Order Functions (map/filter)
# VULN: request.json["ids"] -> map(build_clause, ...) -> join -> cursor.execute (SQL injection)
# ============================================================

def build_clause(record_id):
    """Builds a single SQL clause from a user-supplied ID."""
    return f"id = '{record_id}'"


@app.route("/api/records/bulk-lookup", methods=["POST"])
def bulk_lookup():
    ids = request.json["ids"]
    clauses = list(map(build_clause, ids))
    where = " OR ".join(clauses)
    sql = "SELECT * FROM records WHERE " + where
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(sql)
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(results)


# ============================================================
# 12. Generator Expression + filter (bonus higher-order variant)
# VULN: request.json["usernames"] -> filter -> generator expression -> cursor.execute (SQL injection)
# ============================================================

def is_valid_lookup(username):
    """Filter predicate -- allows any non-empty string through."""
    return len(username) > 0


def build_user_lookup(usernames):
    """Builds a SQL query from filtered usernames via generator expression."""
    valid = filter(is_valid_lookup, usernames)
    in_clause = ", ".join(f"'{u}'" for u in valid)
    return f"SELECT * FROM users WHERE username IN ({in_clause})"


@app.route("/api/users/bulk", methods=["POST"])
def bulk_user_lookup():
    usernames = request.json["usernames"]
    sql = build_user_lookup(usernames)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(sql)
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(results)


# ============================================================
# 13. Class with __init__ Field Propagation + Method Chain
# VULN: request.json -> DataPipeline.__init__ -> transform -> persist -> cursor.execute (SQL injection)
# ============================================================

class DataPipeline:
    """Processes and stores data records with taint flowing through fields."""

    def __init__(self, source_name, raw_data):
        self.source_name = source_name
        self.raw_data = raw_data
        self.transformed = None

    def transform(self):
        """Transforms raw_data, preserving taint in self.transformed."""
        self.transformed = json.dumps(self.raw_data)
        return self

    def persist(self):
        """Stores transformed data via string-concatenated SQL."""
        conn = get_connection()
        cursor = conn.cursor()
        sql = "INSERT INTO pipeline_data (source, payload) VALUES ('" + self.source_name + "', '" + self.transformed + "')"
        cursor.execute(sql)
        conn.commit()
        conn.close()
        return {"status": "persisted"}


@app.route("/api/pipeline/ingest", methods=["POST"])
def ingest_pipeline():
    source = request.json["source"]
    data = request.json["data"]
    pipeline = DataPipeline(source, data)
    result = pipeline.transform().persist()
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)

# ============================================================
# ADDITIONAL PATTERNS - Covering gaps found in flow audit
# ============================================================

# Comprehension with taint flow
def comprehension_flow(items):
    """Taint flows through list/dict comprehensions."""
    results = [eval(x) for x in items]  # list comp
    mapped = {k: eval(v) for k, v in items}  # dict comp
    first = next(x for x in items if x.startswith("cmd:"))  # genexpr
    return results

# Class inheritance chain with virtual dispatch
class BaseProcessor:
    def process(self, data):
        return self.transform(data)
    def transform(self, data):
        return data

class UnsafeProcessor(BaseProcessor):
    def transform(self, data):
        return eval(data)  # override reaches sink

class SafeProcessor(BaseProcessor):
    def transform(self, data):
        return str(data)  # safe override

# Decorator that wraps and passes through taint
def validate_input(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Decorator passes taint through to wrapped function
        return func(*args, **kwargs)
    return wrapper

@validate_input
def execute_command(cmd):
    import os
    os.system(cmd)  # taint flows through decorator

# Exception flow
def exception_taint_flow(data):
    try:
        result = process_data(data)
    except ValueError as e:
        # Exception message may contain tainted data
        import logging
        logging.error(f"Failed: {e}")  # taint via exception
    finally:
        cleanup(data)

# Walrus operator in loop
def walrus_loop(stream):
    while (chunk := stream.read(1024)):
        eval(chunk)  # taint via walrus

# Dataclass with tainted fields
from dataclasses import dataclass

@dataclass
class UserRequest:
    username: str
    query: str

def handle_request(req: UserRequest):
    import os
    os.system(req.query)  # field access taint

# Lambda with taint flow
transform = lambda data: eval(data)  # taint through lambda
