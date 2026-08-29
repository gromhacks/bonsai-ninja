import sqlite3
import os


def verify_token(token):
    conn = sqlite3.connect("auth.db")
    cursor = conn.cursor()
    query = "SELECT user_id FROM tokens WHERE token = '" + token + "'"
    cursor.execute(query)  # sink: SQL injection
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None


def run_admin_command(user_id, cmd):
    if user_id:
        os.system("notify-admin " + cmd)  # sink: command injection
