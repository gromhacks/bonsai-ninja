import os
import sqlite3
import hashlib
import json
from contextlib import contextmanager


class DatabaseConnection:
    """Database connection manager"""

    def __init__(self, connection_string):
        self.connection_string = connection_string
        self._conn = None

    def get_connection(self):
        if self._conn is None:
            db_path = self.connection_string.replace("sqlite:///", "")
            self._conn = sqlite3.connect(db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    @contextmanager
    def transaction(self):
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None


class QueryBuilder:
    """SQL query builder - used in deep chain"""

    def __init__(self, table):
        self.table = table
        self.conditions = []
        self.order = None
        self.limit_val = None

    def where(self, condition):
        """Adds WHERE condition - VULN: unsanitized input"""
        self.conditions.append(condition)
        return self

    def order_by(self, field):
        self.order = field
        return self

    def limit(self, n):
        self.limit_val = n
        return self

    def build(self):
        """Builds final SQL string - VULN: concatenation"""
        sql = f"SELECT * FROM {self.table}"
        if self.conditions:
            sql += " WHERE " + " AND ".join(self.conditions)
        if self.order:
            sql += f" ORDER BY {self.order}"
        if self.limit_val:
            sql += f" LIMIT {self.limit_val}"
        return sql

    def build_safe(self, params):
        """Safe version with parameter placeholders"""
        sql = f"SELECT * FROM {self.table}"
        if self.conditions:
            sql += " WHERE " + " AND ".join("? = ?" for _ in self.conditions)
        return sql, params


class UserRepository:
    """User data access layer"""

    def __init__(self, db):
        self.db = db

    def find_by_username(self, username):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()

    def find_by_id(self, user_id):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()

    def create(self, username, email, password_hash):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        conn.commit()
        return cursor.lastrowid

    def update(self, user_id, fields):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        set_clause = ", ".join(f"{k} = ?" for k in fields.keys())
        values = list(fields.values()) + [user_id]
        cursor.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
        conn.commit()

    def find_by_filter(self, search_query):
        """Deep Chain 1 endpoint: executes the built SQL"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        qb = QueryBuilder("users")
        sql_text = search_query.get_sql()
        cursor.execute(sql_text)
        return [dict(row) for row in cursor.fetchall()]

    def find_by_filter_safe(self, query_text, sort_by):
        """Safe version: parameterized query"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        allowed_sorts = {"name", "email", "created_at"}
        safe_sort = sort_by if sort_by in allowed_sorts else "name"
        sql = f"SELECT * FROM users WHERE name LIKE ? ORDER BY {safe_sort}"
        cursor.execute(sql, ("%" + query_text + "%",))
        return [dict(row) for row in cursor.fetchall()]

    def update_reset_token(self, email, token):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET reset_token = ? WHERE email = ?", (token, email))
        conn.commit()

    def delete(self, user_id):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()


class DocumentRepository:
    """Document data access layer"""

    def __init__(self, db):
        self.db = db

    def create(self, title, path, user_id):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO documents (title, path, user_id) VALUES (?, ?, ?)",
            (title, path, user_id),
        )
        conn.commit()
        return cursor.lastrowid

    def find_by_id(self, doc_id):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
        return cursor.fetchone()

    def find_by_user(self, user_id, offset, limit):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM documents WHERE user_id = ? LIMIT ? OFFSET ?",
            (user_id, limit, offset),
        )
        return [dict(row) for row in cursor.fetchall()]

    def delete(self, doc_id):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        conn.commit()

    def search(self, query):
        """VULN: SQL injection in document search"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        sql = "SELECT * FROM documents WHERE title LIKE '%" + query + "%'"
        cursor.execute(sql)
        return [dict(row) for row in cursor.fetchall()]

    def search_safe(self, query):
        """Safe version"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM documents WHERE title LIKE ?", ("%" + query + "%",))
        return [dict(row) for row in cursor.fetchall()]


class AuditLog:
    """Audit logging for compliance"""

    def __init__(self, db):
        self.db = db

    def log_action(self, user_id, action, details):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)",
            (user_id, action, json.dumps(details)),
        )
        conn.commit()

    def search_logs(self, filter_text):
        """VULN: SQL injection in log search"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        sql = "SELECT * FROM audit_log WHERE details LIKE '%" + filter_text + "%'"
        cursor.execute(sql)
        return [dict(row) for row in cursor.fetchall()]
