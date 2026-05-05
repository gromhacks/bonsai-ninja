"""
Cross-module flow test file.

Imports from ALL 5 existing Python example files and creates 5 distinct
cross-file vulnerability chains. Each chain uses Flask route handlers
as entry points (with request.args/form/json as sources) and calls
imported functions that reach sinks in other files.
"""

import os
import sys
import sqlite3
import subprocess
from flask import Flask, request, jsonify

from database import (
    DatabaseConnection,
    QueryBuilder,
    UserRepository,
    DocumentRepository,
    AuditLog,
)
from services import (
    SearchQuery,
    UserService,
    DocumentService,
    AdminService,
    NotificationService,
)
from utils import (
    sanitize_input,
    ConfigManager,
)
from ml_pipeline import (
    ModelConfig,
    ExternalModelRunner,
    PipelineManager,
)

app = Flask(__name__)
db = DatabaseConnection("app.db")


# ============================================================
# Chain A: Deep Interprocedural SQL Injection (10+ hops, 4 files)
#
# Full chain (cross_module.py -> services.py -> database.py):
#   1.  search_handler()             [cross_module.py] - Flask route, reads request.args
#   2.  enrich_search_params()       [cross_module.py] - adds metadata to query
#   3.  dispatch_search()            [cross_module.py] - selects search strategy
#   4.  execute_user_search()        [cross_module.py] - creates SearchQuery object
#   5.  SearchQuery.__init__()       [services.py]     - stores raw_query
#   6.  SearchQuery.build_filter()   [services.py]     - builds SQL WHERE clause
#   7.  UserRepository.__init__()    [database.py]     - stores db ref
#   8.  UserRepository.find_by_filter() [database.py]  - calls get_sql()
#   9.  SearchQuery.get_sql()        [services.py]     - returns unsanitized SQL
#   10. cursor.execute()             [database.py]     - executes tainted SQL
#
# Tests: deep interprocedural tracking across 3 files with 10+ hops,
#   object construction, method chains, and field propagation.
# ============================================================

# VULN: Chain A - SQL Injection via deep cross-file call chain
# Source: request.args["query"] in search_handler
# Sink: cursor.execute in database.py


def enrich_search_params(raw_query, context):
    """Adds search context metadata. Passes query through unchanged."""
    enriched = raw_query
    if context.get("fuzzy"):
        enriched = enriched + "%"
    return enriched


def dispatch_search(query_text, sort_field, limit, strategy="default"):
    """Selects search strategy and delegates. Query flows through."""
    if strategy == "advanced":
        return execute_user_search(query_text, sort_field, limit)
    return execute_user_search(query_text, sort_field, limit)


def execute_user_search(query_text, sort_field, limit):
    """Creates SearchQuery and delegates to UserRepository.
    query_text flows into SearchQuery -> build_filter -> get_sql -> cursor.execute.
    """
    search_query = SearchQuery(query_text, sort_field, limit)
    search_query.validate()
    search_query.build_filter()
    repo = UserRepository(db)
    return repo.find_by_filter(search_query)


@app.route("/api/cross/search")
def search_handler():
    """Chain A entry point. User input flows through 4 functions in this file,
    then into services.py and database.py for SQL execution.
    """
    raw_query = request.args["query"]
    sort_by = request.args.get("sort", "name")
    limit = request.args.get("limit", "100")
    context = {"fuzzy": True, "source": "api"}
    enriched = enrich_search_params(raw_query, context)
    results = dispatch_search(enriched, sort_by, limit, strategy="advanced")
    return jsonify(results)


# ============================================================
# Chain B: Module-Level Variable Command Injection (2 files)
#
# Full chain (cross_module.py -> ml_pipeline.py):
#   1. capture_handler()             [cross_module.py] - Flask route, reads request.form
#   2. _pending_script_path          [cross_module.py] - module-level variable (bridge)
#   3. execute_pending_handler()     [cross_module.py] - reads module var
#   4. PipelineManager.__init__()    [ml_pipeline.py]  - creates manager
#   5. PipelineManager.run_shell_pipeline() [ml_pipeline.py] - subprocess.run(shell=True)
#
# Tests: module-level variable bridging (bridgeable_vars), cross-function
#   flow via shared module state, and cross-file sink invocation.
# ============================================================

# VULN: Chain B - Command Injection via module-level variable
# Source: request.form["script"] in capture_handler
# Sink: subprocess.run(shell=True) in ml_pipeline.py

_pending_script_path = None


@app.route("/api/cross/capture", methods=["POST"])
def capture_handler():
    """Stores user-controlled script path in module-level variable."""
    global _pending_script_path
    _pending_script_path = request.form["script"]
    return jsonify({"status": "captured"})


@app.route("/api/cross/execute-pending", methods=["POST"])
def execute_pending_handler():
    """Reads the module-level variable and passes to PipelineManager."""
    global _pending_script_path
    if _pending_script_path is None:
        return jsonify({"error": "nothing pending"}), 400
    manager = PipelineManager()
    result = manager.run_shell_pipeline(_pending_script_path)
    _pending_script_path = None
    return jsonify({"output": result})


# ============================================================
# Chain C: Callback/Event Command Injection (3 files)
#
# Full chain (cross_module.py -> services.py):
#   1. trigger_handler()             [cross_module.py] - Flask route, reads request.json
#   2. _on_maintenance_event()       [cross_module.py] - callback function
#   3. AdminService.__init__()       [services.py]     - stores db ref
#   4. AdminService.run_maintenance() [services.py]    - subprocess.run(shell=True)
#
# Tests: callback function stored in dict, invoked with tainted input,
#   delegates to imported class method that reaches sink.
# ============================================================

# VULN: Chain C - Command Injection via callback mechanism
# Source: request.json["payload"] in trigger_handler
# Sink: subprocess.run(shell=True) in services.py AdminService.run_maintenance

_event_handlers = {}


def _on_maintenance_event(task_name):
    """Callback that delegates to AdminService.run_maintenance."""
    svc = AdminService(db)
    return svc.run_maintenance(task_name)


def _on_notification_event(address):
    """Callback that delegates to NotificationService.send_email."""
    notifier = NotificationService()
    notifier.send_email(address, "Event triggered", "Automated notification")
    return {"sent": True}


def register_event_handlers():
    """Registers callbacks into a dictionary for later dispatch."""
    _event_handlers["maintenance"] = _on_maintenance_event
    _event_handlers["notification"] = _on_notification_event


register_event_handlers()


@app.route("/api/cross/trigger", methods=["POST"])
def trigger_handler():
    """Reads user input and dispatches to registered callback."""
    event_type = request.json["type"]
    payload = request.json["payload"]
    handler = _event_handlers.get(event_type)
    if handler is None:
        return jsonify({"error": "unknown event"}), 400
    result = handler(payload)
    return jsonify(result)


# ============================================================
# Chain D: Re-exported Wrapper (3 files)
#
# Full chain (cross_module.py -> services.py -> os.system):
#   1. notify_handler()              [cross_module.py] - Flask route, reads request.form
#   2. send_single_notification()    [cross_module.py] - wrapper function
#   3. NotificationService.__init__() [services.py]    - creates service
#   4. NotificationService.send_email() [services.py]  - os.system(cmd)
#
# Also sub-chain D2 through ml_pipeline.py:
#   1. model_handler()               [cross_module.py] - Flask route, reads request.form
#   2. prepare_and_run_model()       [cross_module.py] - wrapper function
#   3. ExternalModelRunner.__init__() [ml_pipeline.py] - stores config
#   4. ExternalModelRunner.execute()  [ml_pipeline.py] - os.system(cmd)
#
# Tests: import resolution for re-exported/wrapped functions.
# ============================================================

# VULN: Chain D - Command Injection via re-exported wrapper
# Source: request.form["recipient"] in notify_handler
# Sink: os.system in services.py NotificationService.send_email


def send_single_notification(recipient, subject):
    """Wrapper around NotificationService.send_email."""
    notifier = NotificationService()
    notifier.send_email(recipient, subject, "Automated message body")
    return {"status": "sent", "to": recipient}


@app.route("/api/cross/notify", methods=["POST"])
def notify_handler():
    """Chain D1 entry point. User input flows through wrapper to sink."""
    recipient = request.form["recipient"]
    subject = request.form.get("subject", "Alert")
    result = send_single_notification(recipient, subject)
    return jsonify(result)


def prepare_and_run_model(model_path, model_name):
    """Wrapper that creates ExternalModelRunner and calls execute."""
    config = ModelConfig(model_path, model_name)
    config.validate()
    runner = ExternalModelRunner(config)
    resolved = runner.prepare()
    return runner.execute(resolved)


@app.route("/api/cross/run-model", methods=["POST"])
def model_handler():
    """Chain D2 entry point. User input flows to ml_pipeline.py sink."""
    model_path = request.form["model_path"]
    model_name = request.form.get("model_name", "default")
    result = prepare_and_run_model(model_path, model_name)
    return jsonify(result)


# ============================================================
# Chain E: Recursive SQL Injection (3 files)
#
# Full chain (cross_module.py -> database.py):
#   1. audit_handler()               [cross_module.py] - Flask route, reads request.args
#   2. expand_query_recursive()      [cross_module.py] - recursive function
#   3. execute_raw_query()           [cross_module.py] - calls AuditLog.search_logs
#   4. AuditLog.__init__()          [database.py]     - stores db ref
#   5. AuditLog.search_logs()       [database.py]     - cursor.execute(string concat)
#
# Tests: recursive call handling where taint survives through
#   recursive invocations and eventually reaches a cross-file sink.
# ============================================================

# VULN: Chain E - SQL Injection via recursive query expansion
# Source: request.args["filter"] in audit_handler
# Sink: cursor.execute in database.py AuditLog.search_logs


def expand_query_recursive(query_fragment, depth=0):
    """Recursively expands query fragments. Taint survives recursion."""
    if depth > 5:
        return query_fragment
    marker = "{{sub:"
    idx = query_fragment.find(marker)
    if idx == -1:
        return query_fragment
    end_idx = query_fragment.find("}}", idx + len(marker))
    if end_idx == -1:
        return query_fragment
    sub_value = query_fragment[idx + len(marker):end_idx]
    expanded_sub = expand_query_recursive(sub_value, depth + 1)
    result = query_fragment[:idx] + expanded_sub + query_fragment[end_idx + 2:]
    return result


def execute_raw_query(filter_text):
    """Passes the expanded query to AuditLog.search_logs."""
    audit = AuditLog(db)
    return audit.search_logs(filter_text)


@app.route("/api/cross/audit")
def audit_handler():
    """Chain E entry point. Recursively expands user input, then executes."""
    raw_filter = request.args["filter"]
    expanded = expand_query_recursive(raw_filter)
    results = execute_raw_query(expanded)
    return jsonify(results)


# ============================================================
# Safe chain: sanitized input does NOT reach sink
# ============================================================

@app.route("/api/cross/safe")
def safe_handler():
    """Safe variant: input goes through sanitize_input from utils.py."""
    raw = request.args["q"]
    cleaned = sanitize_input(raw)
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name = ?", (cleaned,))
    return jsonify([dict(r) for r in cursor.fetchall()])


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5002)
