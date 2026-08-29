const { execSync } = require("child_process");
const mysql = require("mysql");

const db = mysql.createConnection({ host: "localhost", database: "auth" });

function verifyToken(token) {
  // Inline the SQL string at the call site so the rule's
  // arg-shape SQL-keyword constraint can fire syntactically.
  return db.query("SELECT user_id FROM tokens WHERE token = '" + token + "'");  // sink: SQL injection
}

function runAdminCommand(userId, cmd) {
  if (userId) {
    execSync("notify-admin " + cmd);  // sink: command injection
  }
}

module.exports = { verifyToken, runAdminCommand };
