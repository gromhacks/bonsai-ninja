import { execSync } from "child_process";
import mysql from "mysql";

const db = mysql.createConnection({ host: "localhost", database: "auth" });

export function verifyToken(token: string): string | null {
  // Inline the SQL string at the call site so the rule's
  // arg-shape SQL-keyword constraint can fire syntactically.
  db.query("SELECT user_id FROM tokens WHERE token = '" + token + "'");  // sink: SQL injection
  return token;
}

export function runAdminCommand(userId: string, cmd: string): void {
  if (userId) {
    execSync("notify-admin " + cmd);  // sink: command injection
  }
}
