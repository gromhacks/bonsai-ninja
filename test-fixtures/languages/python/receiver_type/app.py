"""Receiver-type audit fixture (Python).

Two POSITIVE shapes:

  1. Variable named `cursor` — same name as the rule's first attribute
     segment. Worked even before factory-method type inference.

  2. Variable named `cur` — bound to `conn.cursor()`. The engine's
     factory-method-name inference (kit.rs `infer_type_from_factory_method`)
     binds `cur` to type `Cursor`, and the matcher's case-fallback
     accepts the rule's lowercase `[cursor, execute]` against the
     PascalCase rewrite.
"""
import os
import sqlite3


def handle():
    # POSITIVE 1: receiver literally named `cursor`.
    tainted = os.getenv("NAME") or ""
    conn = sqlite3.connect("/tmp/x.db")
    cursor = conn.cursor()
    cursor.execute(tainted)


def handle_chained():
    # POSITIVE 2: receiver bound via chained factory `conn.cursor()`.
    tainted2 = os.getenv("NAME") or ""
    conn2 = sqlite3.connect("/tmp/x.db")
    cur = conn2.cursor()
    cur.execute(tainted2)
