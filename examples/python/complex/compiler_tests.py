"""Compiler architecture test cases for the tree-sitter-sast flow engine.

Each section tests a specific capability with both positive (flow expected)
and negative (no flow expected) scenarios. These complement the automated
tests in tests/langs/ with realistic, readable examples.
"""
import os
import subprocess
import sqlite3


# ---------------------------------------------------------------------------
# 1. BRANCH-AWARE KILL ANALYSIS
# ---------------------------------------------------------------------------
# The engine must detect that taint survives when only one branch kills it.

def branch_kill_both_paths(user_input: str):
    """[NO FLOW EXPECTED] Both branches sanitize -- taint is killed."""
    if len(user_input) > 100:
        cmd = "default_command"
    else:
        cmd = "safe_fallback"
    subprocess.run(cmd, shell=True)  # safe: both paths overwrite cmd


def branch_kill_one_path(user_input: str):
    """[FLOW EXPECTED] Only one branch kills taint -- taint survives."""
    cmd = user_input
    if len(cmd) > 100:
        cmd = "truncated"
    # else: cmd still holds user_input
    subprocess.run(cmd, shell=True)  # tainted: else path preserves input


def branch_kill_nested(user_input: str):
    """[FLOW EXPECTED] Nested branches -- taint survives outer else."""
    data = user_input
    if data.startswith("/"):
        if ".." in data:
            data = "/safe/path"
        # else: data still tainted (starts with / but no ..)
    # else: data still tainted
    with open(data) as f:  # tainted: multiple paths preserve input
        return f.read()


# ---------------------------------------------------------------------------
# 2. INTERPROCEDURAL KILL (2+ levels deep)
# ---------------------------------------------------------------------------

def _sanitize(value: str) -> str:
    """Sanitizer that removes dangerous characters."""
    return value.replace("'", "").replace(";", "").replace("--", "")


def _wrap_sanitize(value: str) -> str:
    """Wrapper around sanitizer -- 2 levels deep."""
    return _sanitize(value)


def interprocedural_kill_direct(user_input: str):
    """[NO FLOW EXPECTED] Sanitizer applied before sink."""
    clean = _sanitize(user_input)
    conn = sqlite3.connect(":memory:")
    conn.execute(f"SELECT * FROM users WHERE name = '{clean}'")


def interprocedural_kill_two_levels(user_input: str):
    """[NO FLOW EXPECTED] Sanitizer 2 levels deep still kills taint."""
    clean = _wrap_sanitize(user_input)
    conn = sqlite3.connect(":memory:")
    conn.execute(f"SELECT * FROM users WHERE name = '{clean}'")


def interprocedural_no_kill(user_input: str):
    """[FLOW EXPECTED] No sanitizer -- taint flows to sink."""
    conn = sqlite3.connect(":memory:")
    conn.execute(f"SELECT * FROM users WHERE name = '{user_input}'")


# ---------------------------------------------------------------------------
# 3. FIELD-SENSITIVE TRACKING
# ---------------------------------------------------------------------------

class Config:
    def __init__(self):
        self.command = ""
        self.label = ""


def field_sensitive_tainted_field(user_input: str):
    """[FLOW EXPECTED] Tainted field flows to sink."""
    cfg = Config()
    cfg.command = user_input
    cfg.label = "safe_label"
    subprocess.run(cfg.command, shell=True)  # tainted: cfg.command = user_input


def field_sensitive_safe_field(user_input: str):
    """[NO FLOW EXPECTED] Only safe field used at sink."""
    cfg = Config()
    cfg.command = user_input
    cfg.label = "safe_label"
    subprocess.run(cfg.label, shell=True)  # safe: cfg.label is constant


def field_sensitive_overwrite(user_input: str):
    """[NO FLOW EXPECTED] Tainted field overwritten before sink."""
    cfg = Config()
    cfg.command = user_input
    cfg.command = "hardcoded_safe"
    subprocess.run(cfg.command, shell=True)  # safe: overwritten


# ---------------------------------------------------------------------------
# 4. EXCEPTION CHAIN TAINT PROPAGATION
# ---------------------------------------------------------------------------

def exception_taint_in_message(user_input: str):
    """[FLOW EXPECTED] Taint flows through exception message."""
    try:
        raise ValueError(f"Invalid input: {user_input}")
    except ValueError as e:
        subprocess.run(str(e), shell=True)  # tainted: exception carries input


def exception_taint_reraise(user_input: str):
    """[FLOW EXPECTED] Taint survives reraise."""
    try:
        cmd = user_input
        result = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        # e.cmd contains the original tainted command
        subprocess.run(f"retry {e.cmd}", shell=True)


# ---------------------------------------------------------------------------
# 5. CONTAINER ELEMENT PRECISION
# ---------------------------------------------------------------------------

def container_element_overwrite(user_input: str):
    """[NO FLOW EXPECTED] Element overwritten after taint."""
    commands = [user_input, "ls", "pwd"]
    commands[0] = "safe_command"
    subprocess.run(commands[0], shell=True)  # safe: element 0 overwritten


def container_append_tainted(user_input: str):
    """[FLOW EXPECTED] Tainted element appended to list."""
    parts = []
    parts.append(user_input)
    query = " ".join(parts)
    conn = sqlite3.connect(":memory:")
    conn.execute(query)


# ---------------------------------------------------------------------------
# 6. MULTI-RETURN PRECISION
# ---------------------------------------------------------------------------

def _fetch_data(source: str) -> tuple:
    """Returns (data, error_message)."""
    return source, "no error"


def multi_return_tainted_position(user_input: str):
    """[FLOW EXPECTED] Position 0 carries taint from call."""
    data, err = _fetch_data(user_input)
    conn = sqlite3.connect(":memory:")
    conn.execute(f"SELECT * FROM t WHERE x = '{data}'")


def multi_return_safe_position(user_input: str):
    """[NO FLOW EXPECTED] Position 1 does not carry call taint."""
    data, err = _fetch_data(user_input)
    subprocess.run(err, shell=True)  # safe: err is "no error" literal


# ---------------------------------------------------------------------------
# 7. TYPE-TRACKED CALL RESOLUTION
# ---------------------------------------------------------------------------

class SafeExecutor:
    def execute(self, cmd: str):
        print(f"Would execute: {cmd}")  # safe: no actual execution


class UnsafeExecutor:
    def execute(self, cmd: str):
        subprocess.run(cmd, shell=True)  # dangerous


def type_tracked_unsafe(user_input: str):
    """[FLOW EXPECTED] UnsafeExecutor.execute reaches subprocess."""
    executor = UnsafeExecutor()
    executor.execute(user_input)


def type_tracked_safe(user_input: str):
    """[NO FLOW EXPECTED] SafeExecutor.execute does not reach subprocess."""
    executor = SafeExecutor()
    executor.execute(user_input)


# ---------------------------------------------------------------------------
# 8. PARAMETER SOURCE SYNTHESIS
# ---------------------------------------------------------------------------
# When a function is never called internally, its parameters are treated
# as external entry points (automatic taint sources).

def handle_webhook(payload: str, signature: str):
    """[FLOW EXPECTED] External entry point -- params are taint sources."""
    subprocess.run(f"process {payload}", shell=True)


def handle_api_request(query: str):
    """[FLOW EXPECTED] External entry point -- param flows to SQL."""
    conn = sqlite3.connect(":memory:")
    conn.execute(f"SELECT * FROM data WHERE q = '{query}'")


# ---------------------------------------------------------------------------
# 9. GENERATOR SEND BRIDGE (Python-specific)
# ---------------------------------------------------------------------------

def _processor():
    """Generator that receives tainted data via .send()."""
    while True:
        data = yield
        if data is None:
            break
        subprocess.run(data, shell=True)  # sink


def generator_send_tainted(user_input: str):
    """[FLOW EXPECTED] Taint flows through generator .send()."""
    gen = _processor()
    next(gen)  # prime
    gen.send(user_input)


# ---------------------------------------------------------------------------
# 10. CROSS-METHOD CLASS FIELD TAINT
# ---------------------------------------------------------------------------

class Pipeline:
    def __init__(self):
        self.data = ""

    def ingest(self, raw: str):
        self.data = raw

    def process(self):
        subprocess.run(self.data, shell=True)  # tainted if ingest() was called with tainted input


def cross_method_field_taint(user_input: str):
    """[FLOW EXPECTED] Taint flows through class field across methods."""
    p = Pipeline()
    p.ingest(user_input)
    p.process()
