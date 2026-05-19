use rusqlite::Connection;
use std::process::Command;

pub fn verify_token(conn: &Connection, token: &str) -> Option<String> {
    let query = format!("SELECT user_id FROM tokens WHERE token = '{}'", token);
    let mut stmt = conn.prepare(&query).ok()?; // sink: SQL injection
    let user_id: String = stmt.query_row([], |row| row.get(0)).ok()?;
    Some(user_id)
}

pub fn run_admin_command(user_id: &str, cmd: &str) {
    if !user_id.is_empty() {
        let full_cmd = format!("notify-admin {}", cmd);
        Command::new("sh")
            .arg("-c")
            .arg(&full_cmd)
            .output()
            .expect("failed"); // sink: command injection
    }
}
