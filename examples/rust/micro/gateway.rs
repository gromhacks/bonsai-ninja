use crate::micro::user_service::{get_user, update_user};
use std::collections::HashMap;

pub fn handle_request(
    conn: &rusqlite::Connection,
    params: &HashMap<String, String>,
) -> String {
    let token = params.get("token").unwrap();    // source: user input
    let action = params.get("action").unwrap();  // source: user input

    let user = get_user(conn, token);           // flows to SQL injection
    let result = update_user(conn, token, action); // flows to command injection

    format!("user: {:?}, result: {:?}", user, result)
}
