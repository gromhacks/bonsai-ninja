use crate::micro::auth_service::{verify_token, run_admin_command};

pub struct UserInfo {
    pub id: String,
    pub token: String,
}

pub fn get_user(conn: &rusqlite::Connection, token: &str) -> Option<UserInfo> {
    let user_id = verify_token(conn, token)?;
    Some(UserInfo {
        id: user_id,
        token: token.to_string(),
    })
}

pub fn update_user(conn: &rusqlite::Connection, token: &str, action: &str) -> Option<String> {
    let user_id = verify_token(conn, token)?;
    run_admin_command(&user_id, action);
    Some(user_id)
}
